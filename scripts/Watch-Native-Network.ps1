param([Parameter(Mandatory=$true)][string]$StateFile,[int]$CorePid,[long]$CoreTicks,[int]$ParentPid,[long]$ParentTicks)
$ErrorActionPreference='Stop'
function Owned-Process([int]$Id,[long]$Ticks){try{$p=Get-Process -Id $Id -ErrorAction Stop;return $p.StartTime.ToUniversalTime().Ticks -eq $Ticks}catch{return $false}}
while((Owned-Process $CorePid $CoreTicks) -and (Owned-Process $ParentPid $ParentTicks)){Start-Sleep -Milliseconds 500}
$mutex=[Threading.Mutex]::new($false,'Local\VPN-Go-Core-Network')
try{
    for($attempt=0;$attempt -lt 3;$attempt++){
        $owned=$false
        try{
            try{$owned=$mutex.WaitOne(30000)}catch [Threading.AbandonedMutexException]{$owned=$true}
            if(!$owned){throw 'Network transaction busy.'}
            if(Test-Path -LiteralPath $StateFile){& (Join-Path $PSScriptRoot 'Set-Windows-Tunnel.ps1') -Mode Restore -StateFile $StateFile}
            break
        }catch{if($attempt -eq 2){$_|Out-File -LiteralPath ($StateFile+'.recovery-error.log') -Encoding UTF8}else{Start-Sleep -Seconds 1}}finally{if($owned){$mutex.ReleaseMutex()}}
    }
    if(Owned-Process $CorePid $CoreTicks){Stop-Process -Id $CorePid -Force -ErrorAction SilentlyContinue}
}finally{$mutex.Dispose()}
