param([Parameter(Mandatory=$true)][string]$NodeLibrary,[string]$Binary='',[string]$Output='')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
if(!$Binary){$Binary=Join-Path $root 'build\windows-amd64\vpn-core.exe'}
if(!$Output){$Output=Join-Path $root ('build\internet-acceptance-'+[guid]::NewGuid().ToString('N'))}
$Output=[IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path $Output|Out-Null
$nodes=Get-Content -LiteralPath $NodeLibrary -Raw|ConvertFrom-Json
$chosen=@($nodes|Where-Object Name -in @('Oracle-Direct-Test-CF','Oracle-Direct-Test-2'))
if($chosen.Count -ne 2){throw 'The acceptance fixture needs both known nodes.'}
$cases=@()
foreach($node in $chosen){$dir=Join-Path $Output $node.Name;New-Item -ItemType Directory -Path $dir|Out-Null;$config=Join-Path $dir 'node.ini';[IO.File]::WriteAllText($config,"node_uri=$($node.Uri)`nconnect_timeout_ms=10000`nidle_timeout_ms=60000`nmax_connections=128`n",[Text.UTF8Encoding]::new($false));$cases+=@{Name=$node.Name;Config=$config;Directory=$dir;ExpectedExitIP=([Uri]$node.Uri).Host}}
$cases|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $Output 'cases.json') -Encoding UTF8
$physical=@(Get-NetAdapter|Where-Object Status -eq Up|Select-Object Name,ifIndex,InterfaceGuid)
$beforeDns=@(Get-DnsClientServerAddress|Where-Object InterfaceIndex -in @($physical.ifIndex)|Sort-Object InterfaceIndex,AddressFamily|Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
@{Physical=$physical;DNS=$beforeDns}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $Output 'network-before.json') -Encoding UTF8
$helper=Join-Path $PSScriptRoot 'Windows-Internet-Acceptance-Worker.ps1'
$admin=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$helper+'"'),'-Binary',('"'+$Binary+'"'),'-Output',('"'+$Output+'"')) -Verb RunAs -WindowStyle Hidden -PassThru
$results=@()
try{
 foreach($case in $cases){
  $readyFile=Join-Path $case.Directory 'ready.json';$deadline=[DateTime]::UtcNow.AddSeconds(100)
  while(!(Test-Path -LiteralPath $readyFile)){if($admin.HasExited){throw 'Native worker failed before readiness.'};if([DateTime]::UtcNow -ge $deadline){throw 'Native session readiness timeout.'};Start-Sleep -Milliseconds 100}
  $ready=Get-Content -LiteralPath $readyFile -Raw|ConvertFrom-Json
  $initial=Get-NetAdapterStatistics -Name $ready.TunName
  $checks=@()
  foreach($site in @(@{Name='cloudflare';URL='https://www.cloudflare.com/cdn-cgi/trace';Marker='ip='},@{Name='example';URL='https://example.com/';Marker='Example Domain'},@{Name='google';URL='https://www.google.com/robots.txt';Marker='User-agent:'})){
   $html=Join-Path $case.Directory ($site.Name+'.html');$errorFile=Join-Path $case.Directory ($site.Name+'.log');$taskBrowserProfile=Join-Path $case.Directory ($site.Name+'-profile')
   # Default DNS and QUIC behavior; no proxy, host pin, IPv4 or TLS override.
   $taskBrowserArgs=@('--headless=new','--no-first-run','--no-default-browser-check',('--user-data-dir="'+$taskBrowserProfile+'"'),'--dump-dom',$site.URL)
   $clock=[Diagnostics.Stopwatch]::StartNew()
   $browser=Start-Process -FilePath 'C:\Program Files\Google\Chrome\Application\chrome.exe' -ArgumentList $taskBrowserArgs -WindowStyle Hidden -RedirectStandardOutput $html -RedirectStandardError $errorFile -PassThru
   $success=$false;$body='';$exit=$null
   if($browser.WaitForExit(30000)){
    for($taskRead=0;$taskRead -lt 20;$taskRead++){try{$body=[IO.File]::ReadAllText($html);break}catch [IO.IOException]{Start-Sleep -Milliseconds 100}}
    $success=$body.Contains($site.Marker);$match=[regex]::Match($body,'(?m)^ip=([^\r\n<]+)');if($match.Success){$exit=$match.Groups[1].Value;$success=$success -and $exit -eq $case.ExpectedExitIP}
   }
   $checks+=@{Site=$site.Name;Success=$success;ExitIP=$exit;Milliseconds=$clock.ElapsedMilliseconds;Bytes=$body.Length}
  }
  $curlBody=Join-Path $case.Directory 'native-ipv6.body';$curlError=Join-Path $case.Directory 'native-ipv6.error'
  $oldPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
  try{& 'C:\Windows\System32\curl.exe' --silent --show-error --connect-timeout 4 --max-time 10 --noproxy '*' --resolve 'www.cloudflare.com:443:[2606:4700::6810:7b60]' --output $curlBody 'https://www.cloudflare.com/cdn-cgi/trace' 2> $curlError;$curlCode=$LASTEXITCODE}finally{$ErrorActionPreference=$oldPreference}
  $curlText=if(Test-Path -LiteralPath $curlBody){[IO.File]::ReadAllText($curlBody)}else{''};$match=[regex]::Match($curlText,'(?m)^ip=([^\r\n]+)')
  $native6=($curlCode -eq 0 -and $match.Success -and $match.Groups[1].Value -eq $case.ExpectedExitIP)
  $final=Get-NetAdapterStatistics -Name $ready.TunName
  $result=@{Node=$case.Name;Browser=$checks;NativeIPv6Destination=$native6;SentBytes=$final.SentBytes-$initial.SentBytes;ReceivedBytes=$final.ReceivedBytes-$initial.ReceivedBytes;CoreVersion=$ready.Version;BrowserProxy=$false;BrowserDNSPinned=$false;BrowserQUICDisabled=$false}
  $result|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $case.Directory 'result.json') -Encoding UTF8
  [IO.File]::WriteAllText((Join-Path $case.Directory 'stop'),'stop')
  $deadline=[DateTime]::UtcNow.AddSeconds(35)
  while(!(Test-Path -LiteralPath (Join-Path $case.Directory 'cleanup.json'))){if([DateTime]::UtcNow -ge $deadline){throw 'Network restoration timeout.'};Start-Sleep -Milliseconds 100}
  $result.Cleanup=Get-Content -LiteralPath (Join-Path $case.Directory 'cleanup.json') -Raw|ConvertFrom-Json
  $results+=$result
 }
 $admin.WaitForExit(30000)|Out-Null
}finally{
 foreach($case in $cases){[IO.File]::WriteAllText((Join-Path $case.Directory 'stop'),'stop')}
 $admin.WaitForExit(30000)|Out-Null
 foreach($case in $cases){if(Test-Path -LiteralPath $case.Config){[IO.File]::WriteAllText($case.Config,'')}}
}
$afterDns=@(Get-DnsClientServerAddress|Where-Object InterfaceIndex -in @($physical.ifIndex)|Sort-Object InterfaceIndex,AddressFamily|Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
$dnsRestored=(ConvertTo-Json -InputObject $beforeDns -Depth 5 -Compress) -ceq (ConvertTo-Json -InputObject $afterDns -Depth 5 -Compress)
$success=$dnsRestored -and @($results|Where-Object { !$_.NativeIPv6Destination -or @($_.Browser|Where-Object Success -ne $true).Count -gt 0 -or !$_.Cleanup.Recovered -or $_.SentBytes -lt 128 -or $_.ReceivedBytes -lt 128 }).Count -eq 0
@{Success=$success;Results=$results;DNSRestored=$dnsRestored;Time=[DateTime]::UtcNow.ToString('O')}|ConvertTo-Json -Depth 9|Set-Content -LiteralPath (Join-Path $Output 'results.json') -Encoding UTF8
Get-Content -LiteralPath (Join-Path $Output 'results.json') -Raw
if(!$success){throw 'Internet acceptance failed; see the result files.'}
