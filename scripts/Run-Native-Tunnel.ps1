[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Config,[string]$Binary='', [string]$StateFile='', [string]$Exchange='')
$ErrorActionPreference='Stop'
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Native network setup requires Run as Administrator.'}
if(!$Binary){$Binary=Join-Path $PSScriptRoot 'vpn-core.exe'}
$Binary=[IO.Path]::GetFullPath($Binary);$Config=[IO.Path]::GetFullPath($Config)
if(!$StateFile){$StateFile=Join-Path $env:LOCALAPPDATA 'VPN-Go-Core\network-session.json'}
$StateFile=[IO.Path]::GetFullPath($StateFile)
if(Test-Path -LiteralPath $StateFile){throw "Restore the previous session first: $StateFile"}
$policy=Join-Path $PSScriptRoot 'Set-Windows-Tunnel.ps1'
$mutex=[Threading.Mutex]::new($false,'Local\VPN-Go-Core-Network');$locked=$false
function Invoke-OwnedPolicy([string]$Mode,$Arguments){
    $owned=$false
    try{$owned=$mutex.WaitOne(30000)}catch [Threading.AbandonedMutexException]{$owned=$true}
    if(!$owned){throw 'Another network transaction is still running.'}
    try{if($Mode -eq 'Restore'){if(Test-Path -LiteralPath $StateFile){& $policy -Mode Restore -StateFile $StateFile}}else{& $policy @Arguments}}finally{$mutex.ReleaseMutex()}
}
$directory=Join-Path ([IO.Path]::GetTempPath()) ('VPN-Go-Core-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory|Out-Null
$temporary=Join-Path $directory 'node.ini';$ready=Join-Path $directory 'core-ready.json';$log=Join-Path $directory 'core.log'
$process=$null;$watcher=$null;$restoreError=$null
try{
    $defaults=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore|Where-Object NextHop -ne '0.0.0.0')
    $primary=$defaults|Sort-Object @{Expression={$_.RouteMetric+(Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric}}|Select-Object -First 1
    if(!$primary){$primary=Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -PolicyStore ActiveStore|Where-Object NextHop -ne '::'|Select-Object -First 1}
    if(!$primary){throw 'A physical upstream route is required.'}
    $physical=Get-NetAdapter -InterfaceIndex $primary.InterfaceIndex -ErrorAction Stop
    $lines=@(Get-Content -LiteralPath $Config|Where-Object {$_ -notmatch '^\s*(listen_port|ready_file|sniffing|native_dns|prefer_ipv4|prefer_tcp)\s*='})
    $lines+=@('listen_port=0',"ready_file=$ready",'sniffing=true','native_dns=true','prefer_ipv4=true','prefer_tcp=true')
    [IO.File]::WriteAllText($temporary,($lines -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
    & $Binary --check-config --config $temporary
    if($LASTEXITCODE -ne 0){throw 'Core configuration validation failed.'}
    $name='VPN-Go-'+[guid]::NewGuid().ToString('N').Substring(0,10)
    $arguments=@('--config',('"'+$temporary+'"'),'--tun',$name,'--dns-listen','127.0.0.1:53','--bind-interface',('"'+$physical.Name+'"'))
    $process=Start-Process -FilePath $Binary -ArgumentList $arguments -WorkingDirectory (Split-Path $Binary -Parent) -WindowStyle Hidden -RedirectStandardOutput (Join-Path $directory 'stdout.log') -RedirectStandardError $log -PassThru
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    do{
        if($process.HasExited){throw "Core stopped before TUN readiness; see $log"}
        $status=$null
        if(Test-Path -LiteralPath $ready){$status=Get-Content -LiteralPath $ready -Raw|ConvertFrom-Json}
        if($status -and $status.tun_name){break}
        if([DateTime]::UtcNow -ge $deadline){throw 'Native TUN readiness timeout.'}
        Start-Sleep -Milliseconds 100
    }while($true)
    $coreTicks=$process.StartTime.ToUniversalTime().Ticks
    $parentTicks=(Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks
    $watchArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $PSScriptRoot 'Watch-Native-Network.ps1')+'"'),'-StateFile',('"'+$StateFile+'"'),'-CorePid',$process.Id,'-CoreTicks',$coreTicks,'-ParentPid',$PID,'-ParentTicks',$parentTicks)
    $watcher=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $watchArgs -WindowStyle Hidden -PassThru
    $up6=@($status.upstream_ipv6|Where-Object {$_})
    if(!(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue)){$up6=@()}
    $dns6=if($status.dns_ipv6){@('::1')}else{@()}
    $apply=@{Mode='Apply';TunName=$name;StateFile=$StateFile;UpstreamIPv4=@($status.upstream_ipv4|Where-Object {$_});UpstreamIPv6=$up6;UpstreamPort=$status.upstream_port;DnsIPv4=@('127.0.0.1');DnsIPv6=$dns6}
    Invoke-OwnedPolicy 'Apply' $apply
    $session=[ordered]@{CorePid=$process.Id;TunName=$name;Version=$status.version;ProxyPort=$status.port;Directory=$directory;StateFile=$StateFile;PhysicalInterface=$physical.Name;Time=[DateTime]::UtcNow.ToString('O')}
    if($Exchange){
        New-Item -ItemType Directory -Path $Exchange -Force|Out-Null
        $session|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Exchange 'ready.json') -Encoding UTF8
        $deadline=[DateTime]::UtcNow.AddSeconds(150)
        while(!(Test-Path -LiteralPath (Join-Path $Exchange 'stop'))){if($process.HasExited){throw 'Core stopped during the native session.'};if([DateTime]::UtcNow -ge $deadline){throw 'Acceptance coordinator timeout.'};Start-Sleep -Milliseconds 100}
    }else{
        Write-Host 'Native tunnel ready. DNS is inside the Go core. Press Ctrl+C to disconnect.'
        $process.WaitForExit()
    }
}finally{
    try{Invoke-OwnedPolicy 'Restore' $null}catch{$restoreError=$_.Exception.Message;Write-Warning $restoreError}
    if($process -and !$process.HasExited){$process.Kill();$process.WaitForExit(5000)|Out-Null}
    if($watcher){$watcher.WaitForExit(15000)|Out-Null;$watcher.Dispose()}
    if($process){$process.Dispose()}
    if(Test-Path -LiteralPath $temporary){[IO.File]::WriteAllText($temporary,'')}
    if($Exchange){@{Recovered=(!(Test-Path -LiteralPath $StateFile));Error=$restoreError;Logs=$directory}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Exchange 'cleanup.json') -Encoding UTF8}
    $mutex.Dispose()
}
if($restoreError){throw "Network restoration needs retry: $restoreError"}
