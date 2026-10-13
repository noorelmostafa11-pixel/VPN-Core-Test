$ErrorActionPreference='Stop'
function Assert($condition,$message){if(!$condition){throw $message}}
$root=Split-Path $PSScriptRoot -Parent
function Load-TestFunction($file,$name){
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
    Assert (!$errors) 'Script has syntax errors.'
    $func=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    Assert ($null -ne $func) 'Expected lifecycle function missing.'
    return [ScriptBlock]::Create($func.Extent.Text)
}
. (Load-TestFunction (Join-Path $root 'scripts\Run-Native-Tunnel.ps1') 'Test-SessionOwner')
. (Load-TestFunction (Join-Path $root 'scripts\Watch-Native-Network.ps1') 'Owned-Process')
$taskTime=[DateTime]::Parse('2026-10-13T00:00:00Z').ToUniversalTime()
function Get-Process {param($Id,$ErrorAction) if($Id -ne 42){throw 'No process'};return [pscustomobject]@{StartTime=$taskTime}}
$OwnerPid=0;$OwnerTicks=0;Assert (Test-SessionOwner) 'Standalone sessions unexpectedly require an app owner.'
$OwnerPid=42;$OwnerTicks=$taskTime.Ticks;Assert (Test-SessionOwner) 'Live external owner rejected.'
$OwnerTicks++;Assert (!(Test-SessionOwner)) 'PID reuse was accepted.'
$OwnerPid=43;Assert (!(Test-SessionOwner)) 'Exited external owner was accepted.'
Assert (Owned-Process 42 $taskTime.Ticks) 'Watcher rejected live process.'
Assert (!(Owned-Process 42 ($taskTime.Ticks+1))) 'Watcher accepted reused PID.'
Assert (!(Owned-Process 43 $taskTime.Ticks)) 'Watcher accepted exited process.'
Write-Output 'PASS: optional external owner, normal parent identity, exit and PID reuse checks.'
Import-Module (Join-Path $root 'scripts\Windows-Tunnel.psm1') -Force
& (Get-Module Windows-Tunnel) {
    $script:taskAdded=0;$script:taskRead=0
    function New-NetIPAddress {param($InterfaceIndex,$AddressFamily,$IPAddress,$PrefixLength,$SkipAsSource,$ErrorAction) $script:taskAdded++}
    function Get-NetIPAddress {param($InterfaceIndex,$AddressFamily,$IPAddress,$ErrorAction)
        if($script:taskAdded -ne 2){throw 'Address readiness was checked before both families were configured.'}
        if($IPAddress -ne [Net.IPAddress]::Parse($IPAddress).ToString()){throw 'CIM address was not normalized.'}
        $script:taskRead++;return [pscustomobject]@{AddressState='Preferred'}
    }
    $state=@{TunIndex=77;TunAddresses=@(@{Family='IPv4';Address='10.248.231.1';Prefix=30},@{Family='IPv6';Address='fd48:248:0491::1';Prefix=64})}
    $ops=Get-VpnWindowsOperations
    & $ops.AddAddress $state
    if($script:taskAdded -ne 2 -or $script:taskRead -ne 2){throw 'Address readiness coverage missing.'}
}
Write-Output 'PASS: both families are configured before readiness polling; normalized address checks remain enforced.'
