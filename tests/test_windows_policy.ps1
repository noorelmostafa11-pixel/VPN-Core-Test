# Transaction fault injection; no network cmdlet is invoked in these tests.
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '..\scripts\Windows-Tunnel.psm1') -Force
function Assert($Condition,[string]$Message) { if (!$Condition) { throw $Message } }
$ranges=@(Get-VpnBlockedIPv4Ranges @('84.235.245.14','84.235.245.15','1.1.1.1','1.1.1.1'))
Assert (($ranges -join ',') -eq '0.0.0.0-1.1.1.0,1.1.1.2-84.235.245.13,84.235.245.16-255.255.255.255') 'Upstream complement left a gap'
Assert ((@(Get-VpnBlockedIPv4Ranges @('0.0.0.0','255.255.255.255')) -join ',') -eq '0.0.0.1-255.255.255.254') 'Boundary complement failed'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('vpn-policy-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$path=Join-Path $temp 'session.json'
try {
    for ($fault=0; $fault -le 8; $fault++) {
        $script:step=0; $script:fault=$fault; $script:rules=@{}; $script:routes=@{}; $script:dns=@{1='DHCP';2='9.9.9.9'}; $script:address=$false; $script:metric=25
        $ops=@{
            AddRule={param($r) $script:rules[$r.Name]=$true; $script:step++; if ($script:step -eq $script:fault) { throw 'injected' }}
            RemoveRule={param($r) $script:rules.Remove($r.Name)}
            AddAddress={param($s) $script:address=$true; $script:step++; if ($script:step -eq $script:fault) { throw 'injected' }}
            RemoveAddress={param($s) $script:address=$false}
            SetMetric={param($s) $script:metric=1; $script:step++; if ($script:step -eq $script:fault) { throw 'injected' }}
            RestoreMetric={param($s) $script:metric=$s.TunMetric.Value}
            AddRoute={param($r) $script:routes[$r.Prefix]=$true; $script:step++; if ($script:step -eq $script:fault) { throw 'injected' }}
            RemoveRoute={param($r) $script:routes.Remove($r.Prefix)}
            SetDNS={param($d,$servers) $script:dns[[int]$d.Index]='1.1.1.1'; $script:step++; if ($script:step -eq $script:fault) { throw 'injected' }}
            RestoreDNS={param($d) $script:dns[[int]$d.Index]= $(if ($d.Static) {$d.Servers[0]} else {'DHCP'})}
            FlushDNS={}
        }
        $state=@{Schema='vpn-windows-session-v1';Phase='Plan';TunMetric=@{Value=25};DnsIPv4=@('1.1.1.1');DNS=@(@{Index=1;Static=$false;Servers=@('10.0.0.53')},@{Index=2;Static=$true;Servers=@('9.9.9.9')});Routes=@(@{Prefix='0.0.0.0/1'},@{Prefix='128.0.0.0/1'});Rules=@(@{Name='owned1'},@{Name='owned2'})}
        $failed=$false
        try { Invoke-VpnWindowsPlan $state $path $ops } catch { $failed=$true }
        if ($fault -eq 0) {
            Assert (!$failed) 'Successful transaction failed'
            Assert ((Test-Path -LiteralPath $path) -and $script:rules.Count -eq 2 -and $script:routes.Count -eq 2) 'Missing active recovery state'
            $old=(Get-Content -LiteralPath $path -Raw)
            $duplicate=$false; try { Invoke-VpnWindowsPlan $state $path $ops } catch { $duplicate=$true }
            Assert ($duplicate -and (Get-Content -LiteralPath $path -Raw) -eq $old) 'Duplicate apply overwrote original state'
            $ops.RestoreDNS={param($d) throw 'injected restore failure'}
            $restoreFailed=$false; try { Restore-VpnWindowsPlan $state $path $ops } catch { $restoreFailed=$true }
            Assert ($restoreFailed -and (Test-Path -LiteralPath $path) -and $script:rules.Count -eq 2) 'Failed restore removed guards or recovery state'
            $ops.RestoreDNS={param($d) $script:dns[[int]$d.Index]= $(if ($d.Static) {$d.Servers[0]} else {'DHCP'})}
            $saved=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            Restore-VpnWindowsPlan $saved $path $ops
        } else { Assert $failed "Failure $fault was not injected" }
        Assert (!(Test-Path -LiteralPath $path)) "State not retired after recovery $fault"
        Assert ($script:rules.Count -eq 0 -and $script:routes.Count -eq 0 -and !$script:address -and $script:metric -eq 25) "Network transaction not reversed $fault"
        Assert ($script:dns[1] -eq 'DHCP' -and $script:dns[2] -eq '9.9.9.9') "Original DNS mode not restored $fault"
    }
    Write-Output 'PASS: ranges, apply, duplicate prevention, all 8 partial failures, failed restore guard retention and retry'
} finally {
    # Only this test's verified temporary directory is removed.
    if (([IO.Path]::GetFullPath($temp)).StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
