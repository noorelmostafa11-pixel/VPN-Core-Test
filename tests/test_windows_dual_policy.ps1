$ErrorActionPreference='Stop'
$taskNetwork=Join-Path $PSScriptRoot '..\scripts'
Import-Module (Join-Path $taskNetwork 'Windows-Tunnel.psm1') -Force
function Assert($condition,[string]$message) { if(!$condition) { throw $message } }
# Read-only plan tests use synthetic adapters, including a literal special name.
function Get-NetAdapter {
    param($Name,[switch]$IncludeHidden,$ErrorAction)
    if($IncludeHidden) { throw 'Hidden miniports must not enter the firewall plan.' }
    if($Name) { return [pscustomobject]@{Name='VPN-Go-Test';Status='Up';ifIndex=77;InterfaceGuid='11111111-1111-4111-8111-111111111111'} }
    return @([pscustomobject]@{Name='Wi-Fi';Status='Up';ifIndex=7;InterfaceGuid='22222222-2222-4222-8222-222222222222'},
        [pscustomobject]@{Name='Ethernet [Lab]*';Status='Up';ifIndex=8;InterfaceGuid='33333333-3333-4333-8333-333333333333'})
}
function Get-NetRoute {
    param($AddressFamily,$DestinationPrefix,$PolicyStore,$InterfaceIndex,$ErrorAction)
    if($DestinationPrefix -eq '0.0.0.0/0') { return [pscustomobject]@{InterfaceIndex=7;NextHop='192.0.2.1';RouteMetric=10} }
    if($DestinationPrefix -eq '::/0') { return [pscustomobject]@{InterfaceIndex=7;NextHop='fe80::1';RouteMetric=10} }
}
function Get-NetIPInterface {
    param($InterfaceIndex,$AddressFamily,$ErrorAction)
    return [pscustomobject]@{AutomaticMetric='Enabled';InterfaceMetric=25;Dhcp='Enabled'}
}
function Get-DnsClientServerAddress {
    param($InterfaceIndex,$AddressFamily,$ErrorAction)
    $servers=if($AddressFamily -eq 'IPv4') { @('192.0.2.53') } else { @('2001:db8::53') }
    return [pscustomobject]@{ServerAddresses=$servers}
}
function Get-NetIPAddress { param($IPAddress,$ErrorAction) }
function Get-NetFirewallProfile { param($PolicyStore) return [pscustomobject]@{Enabled='True'} }
function Get-ItemProperty { param($LiteralPath,$ErrorAction) return [pscustomobject]@{NameServer=''} }
function New-NetRoute { throw 'Plan attempted a real network mutation.' }
function New-NetIPAddress { throw 'Plan attempted a real network mutation.' }
function New-NetFirewallRule { throw 'Plan attempted a real network mutation.' }
$taskTemp=Join-Path ([IO.Path]::GetTempPath()) ('vpn-dual-policy-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskTemp | Out-Null
$taskStateFile=Join-Path $taskTemp 'session.json'
$taskPlan=(& (Join-Path $taskNetwork 'Set-Windows-Tunnel.ps1') -Mode Plan -TunName VPN-Go-Test -UpstreamIPv4 192.0.2.10 -UpstreamIPv6 2001:db8::10 -DnsIPv4 127.0.0.1 -StateFile $taskStateFile -FirewallGuard) -join "`n" | ConvertFrom-Json
Assert ($taskPlan.Schema -eq 'vpn-windows-session-v2') 'Incorrect dual-stack state schema.'
Assert (@($taskPlan.Routes | Where-Object Family -eq 'IPv6').Count -eq 3) 'Missing IPv6 bypass/split routes.'
Assert (@($taskPlan.TunAddresses).Count -eq 2 -and @($taskPlan.TunMetrics).Count -eq 2) 'Missing one address family.'
Assert (@($taskPlan.DNS | Where-Object Family -eq 'IPv6').Count -eq 3) 'IPv6 DNS original state missing.'
Assert ($taskPlan.DNS.Where({$_.Index -eq 77 -and $_.Family -eq 'IPv4'})[0].TargetServers[0] -eq '127.0.0.1') 'Local DNS bridge was not selected.'
Assert ($taskPlan.DNS.Where({$_.Index -eq 7 -and $_.Family -eq 'IPv4'})[0].TargetServers[0] -eq '127.0.0.1') 'Physical DNS was left on DHCP fallback servers.'
Assert (@($taskPlan.Rules | Where-Object { $_.Name -like '*-IPv6' -or $_.Addresses -contains '::/0' }).Count -eq 0) 'IPv6 blanket block remains.'
Assert ($taskPlan.Rules[0].Interfaces[1] -eq 'Ethernet [Lab]*') 'Firewall aliases were incorrectly escaped.'
Assert (!(Test-Path -LiteralPath $taskStateFile)) 'Plan wrote recovery state.'
$taskV6Plan=(& (Join-Path $taskNetwork 'Set-Windows-Tunnel.ps1') -Mode Plan -TunName VPN-Go-Test -UpstreamIPv6 2001:db8::10 -StateFile $taskStateFile) -join "`n" | ConvertFrom-Json
Assert (@($taskV6Plan.Routes).Count -eq 5) 'IPv6 upstream did not receive a bypass plus four tunnel routes.'
Assert (@($taskV6Plan.Rules).Count -eq 0) 'Test mode unexpectedly enabled a firewall block.'
Assert (@($taskV6Plan.DNS | Where-Object Family -eq 'IPv6' | ForEach-Object TargetServers | Where-Object { $_ }).Count -eq 0) 'Unverified IPv6 DNS resolvers are enabled by default.'
Write-Output 'PASS: dual-stack plans, IPv6 upstream, DNS families, exact aliases, no hidden adapters, no IPv6 block, no plan mutations.'

$taskOriginalRoutes=${function:Get-NetRoute}
function Get-NetRoute {
    param($AddressFamily,$DestinationPrefix,$PolicyStore,$InterfaceIndex,$ErrorAction)
    if($DestinationPrefix -eq '192.0.2.10/32'){return [pscustomobject]@{InterfaceIndex=7;NextHop='192.0.2.1';RouteMetric=1}}
    if($DestinationPrefix -eq '0.0.0.0/0'){return [pscustomobject]@{InterfaceIndex=7;NextHop='192.0.2.1';RouteMetric=10}}
}
$taskReuse=(& (Join-Path $taskNetwork 'Set-Windows-Tunnel.ps1') -Mode Plan -TunName VPN-Go-Test -UpstreamIPv4 192.0.2.10 -StateFile $taskStateFile) -join "`n"|ConvertFrom-Json
Assert (@($taskReuse.Routes|Where-Object Prefix -eq '192.0.2.10/32').Count -eq 0) 'Pre-existing physical bypass was incorrectly claimed by the session.'
${function:Get-NetRoute}=$taskOriginalRoutes
Write-Output 'PASS: pre-existing valid physical bypass remains outside owned cleanup.'

function Step { $script:step++; if($script:step -eq $script:fault) { throw 'injected operation failure' } }
$taskApplySteps=@($taskPlan.Rules).Count+@($taskPlan.TunAddresses).Count+@($taskPlan.TunMetrics).Count+@($taskPlan.Routes).Count+@($taskPlan.DNS).Count+1
for($fault=0;$fault -le $taskApplySteps;$fault++) {
    $script:step=0; $script:fault=$fault; $script:rules=@{}; $script:routes=@{}; $script:addresses=@{}; $script:metrics=@{IPv4=25;IPv6=25}; $script:dns=@{}
    foreach($d in $taskPlan.DNS) { $script:dns["$($d.Index)-$($d.Family)"]=($d.Servers -join ',') }
    $originalDNS=$script:dns.Clone()
    $ops=@{
        AddRule={param($r) $script:rules[$r.Name]=$true; Step}
        RemoveRule={param($r) $script:rules.Remove($r.Name)}
        AddAddress={param($s) foreach($a in $s.TunAddresses) { $script:addresses[$a.Address]=$true; Step }}
        RemoveAddress={param($s) foreach($a in $s.TunAddresses) { $script:addresses.Remove($a.Address) }}
        SetMetric={param($s) foreach($m in $s.TunMetrics) { $script:metrics[$m.Family]=1; Step }}
        RestoreMetric={param($s) foreach($m in $s.TunMetrics) { $script:metrics[$m.Family]=$m.Value }}
        AddRoute={param($r) $script:routes[$r.Prefix]=$true; Step}
        RemoveRoute={param($r) $script:routes.Remove($r.Prefix)}
        SetDNS={param($d,$servers) $script:dns["$($d.Index)-$($d.Family)"]=($servers -join ','); Step}
        RestoreDNS={param($d) $script:dns["$($d.Index)-$($d.Family)"]=($d.Servers -join ',')}
        FlushDNS={Step}
    }
    $failed=$false
    try { Invoke-VpnWindowsPlan $taskPlan $taskStateFile $ops } catch { $failed=$true }
    if(!$failed) {
        Assert ($script:addresses.Count -eq 2 -and $script:routes.Count -eq 6) 'Incomplete active dual-stack session.'
        $duplicate=$false; try { Invoke-VpnWindowsPlan $taskPlan $taskStateFile $ops } catch { $duplicate=$true }
        Assert $duplicate 'Duplicate session was accepted.'
        Restore-VpnWindowsPlan $taskPlan $taskStateFile $ops
    }
    Assert ($script:rules.Count -eq 0 -and $script:routes.Count -eq 0 -and $script:addresses.Count -eq 0) 'Partial failure left owned network resources.'
    Assert ($script:metrics.IPv4 -eq 25 -and $script:metrics.IPv6 -eq 25) 'Metric restoration failed.'
    foreach($key in $originalDNS.Keys) { Assert ($script:dns[$key] -eq $originalDNS[$key]) 'DNS restoration failed.' }
    Assert (!(Test-Path -LiteralPath $taskStateFile)) 'Successful rollback retained recovery state.'
}
Write-Output 'PASS: apply/restore and injected failures across both IP families; duplicate prevention; resource cleanup.'
$script:step=0; $script:fault=0
Invoke-VpnWindowsPlan $taskPlan $taskStateFile $ops
$restoreDNS=$ops.RestoreDNS
$ops.RestoreDNS={throw 'injected restore failure'}
$failed=$false; try { Restore-VpnWindowsPlan $taskPlan $taskStateFile $ops } catch { $failed=$true }
Assert ($failed -and (Test-Path -LiteralPath $taskStateFile) -and $script:rules.Count -gt 0) 'Failed recovery discarded its state or guards.'
$ops.RestoreDNS=$restoreDNS
Restore-VpnWindowsPlan $taskPlan $taskStateFile $ops
Assert (!(Test-Path -LiteralPath $taskStateFile) -and $script:rules.Count -eq 0) 'Recovery retry did not complete.'
Write-Output 'PASS: failed restoration retains state/guards, then retry restores both families.'
$script:step=0; $script:fault=0
Invoke-VpnWindowsPlan $taskPlan $taskStateFile $ops
$restoreMetric=$ops.RestoreMetric
$ops.RestoreMetric={throw 'injected TUN metric failure'}
Restore-VpnWindowsPlan $taskPlan $taskStateFile $ops
Assert (!(Test-Path -LiteralPath $taskStateFile) -and $script:rules.Count -eq 0 -and $script:routes.Count -eq 0) 'Disposable TUN metric failure prevented disconnect.'
$ops.RestoreMetric=$restoreMetric
Write-Output 'PASS: TUN metric failure does not keep network guards or routes active.'
