<#
Optional IPv4 host policy for an already running native Wintun core.
Plan is read-only. Apply changes current routes, IPv4 DNS and firewall guards.
Restore reads the saved transaction and restores it. No node credentials stored.
Requires literal upstream IPv4 addresses, including alternate download servers.
IPv6 on the guarded interfaces is blocked, not forwarded by this IPv4 helper.
#>
[CmdletBinding()]
param(
    [ValidateSet('Plan','Apply','Restore')][string]$Mode='Plan',
    [string]$TunName='VPN-Core',
    [string]$PhysicalInterfaceAlias='',
    [string[]]$UpstreamIPv4=@(),
    [ValidateRange(1,65535)][int]$UpstreamPort=443,
    [string[]]$DnsIPv4=@('1.1.1.1','1.0.0.1'),
    [string]$TunAddress='10.248.231.1',
    [string]$StateFile=(Join-Path $env:ProgramData 'VPN-Core\windows-session.json')
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Windows-Tunnel.psm1') -Force
if ($env:OS -ne 'Windows_NT') { throw 'This host policy requires Windows' }
if ($Mode -ne 'Plan') {
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Apply/Restore requires an Administrator PowerShell window' }
}
$StateFile=[IO.Path]::GetFullPath($StateFile)
if ($Mode -eq 'Restore') {
    $state=Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    Restore-VpnWindowsPlan $state $StateFile
    Write-Output 'RESTORED: routes, IPv4 DNS and session firewall guards'
    return
}
if (@($UpstreamIPv4).Count -eq 0) { throw 'Supply every literal upstream IPv4 address using -UpstreamIPv4' }
foreach ($address in @($UpstreamIPv4)+@($DnsIPv4)+@($TunAddress)) {
    $ip=[Net.IPAddress]::Parse($address)
    if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or [Net.IPAddress]::IsLoopback($ip) -or $ip.GetAddressBytes()[0] -eq 0 -or $ip.GetAddressBytes()[0] -ge 224) { throw 'Only unicast IPv4 addresses are accepted' }
}
$tun=Get-NetAdapter -Name $TunName -ErrorAction Stop
if (@($tun).Count -ne 1 -or $tun.Status -ne 'Up') { throw 'Start the native core and wait for its Wintun adapter to be Up first' }
$interfaces=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.Status -eq 'Up' -and $_.ifIndex -ne $tun.ifIndex })
if ($interfaces.Count -eq 0) { throw 'No active underlying interfaces' }
$defaults=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -ne $tun.ifIndex -and $_.NextHop -ne '0.0.0.0' })
if ($PhysicalInterfaceAlias) { $defaults=@($defaults | Where-Object InterfaceAlias -eq $PhysicalInterfaceAlias) }
$route=$defaults | Sort-Object @{Expression={ $_.RouteMetric+(Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric }} | Select-Object -First 1
if (!$route) { throw 'A physical IPv4 default route is required' }
if ((Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object Enabled -ne 'True')) { throw 'All Windows firewall profiles must be enabled for this guard' }
$metric=Get-NetIPInterface -InterfaceIndex $tun.ifIndex -AddressFamily IPv4
$dns=@()
foreach ($a in @($interfaces)+@($tun)) {
    $inputObject=Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (!$inputObject) {
        if ($a.ifIndex -eq $tun.ifIndex) { throw 'Wintun IPv4 DNS registration is not ready; retry the plan shortly' }
        continue # active adapters with no IPv4 binding still receive firewall guards
    }
    $registry=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+([Guid]$a.InterfaceGuid).ToString('B'))
    $static=$registry.PSObject.Properties['NameServer']
    $dns+=@{Index=[int]$a.ifIndex;Guid=[string]$a.InterfaceGuid;Static=($null -ne $static -and ![string]::IsNullOrWhiteSpace([string]$static.Value));Servers=@($inputObject.ServerAddresses)}
}
$routes=@()
$physical=$interfaces | Where-Object ifIndex -eq $route.InterfaceIndex
foreach ($ip in @($UpstreamIPv4 | Sort-Object -Unique)) { $routes+=@{Prefix="$ip/32";Index=[int]$route.InterfaceIndex;Guid=[string]$physical.InterfaceGuid;NextHop=[string]$route.NextHop} }
foreach ($prefix in @('0.0.0.0/1','128.0.0.0/1')) { $routes+=@{Prefix=$prefix;Index=[int]$tun.ifIndex;Guid=[string]$tun.InterfaceGuid;NextHop='0.0.0.0'} }
foreach ($r in $routes) {
    if (Get-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $r.Index -PolicyStore ActiveStore -ErrorAction SilentlyContinue) { throw 'A planned route already exists; refuse to take ownership of it' }
}
if (Get-NetIPAddress -IPAddress $TunAddress -ErrorAction SilentlyContinue) { throw 'The planned TUN address already exists' }
$group='VPN-Core-Session-'+[Guid]::NewGuid().ToString('N')
$aliases=@($interfaces | ForEach-Object { [Management.Automation.WildcardPattern]::Escape($_.Name) })
$rules=@(
    @{Name=$group+'-IPv4';Group=$group;Interfaces=$aliases;Addresses=@(Get-VpnBlockedIPv4Ranges $UpstreamIPv4);Protocol='Any';Ports=@()},
    @{Name=$group+'-IPv6';Group=$group;Interfaces=$aliases;Addresses=@('::/0');Protocol='Any';Ports=@()}
)
$ports=@()
if ($UpstreamPort -gt 1) { $ports+=('1-'+($UpstreamPort-1)) }
if ($UpstreamPort -lt 65535) { $ports+=(($UpstreamPort+1).ToString()+'-65535') }
foreach ($protocol in @('TCP','UDP')) { $rules+=@{Name=$group+'-'+$protocol;Group=$group;Interfaces=$aliases;Addresses=@($UpstreamIPv4);Protocol=$protocol;Ports=$ports} }
$state=@{Schema='vpn-windows-session-v1';Phase='Plan';Group=$group;TunIndex=[int]$tun.ifIndex;TunGuid=[string]$tun.InterfaceGuid;TunAddress=$TunAddress;TunMetric=@{Automatic=[string]$metric.AutomaticMetric;Value=[int]$metric.InterfaceMetric;DHCP=[string]$metric.Dhcp};DNS=$dns;DnsIPv4=$DnsIPv4;Routes=$routes;Rules=$rules}
if ($Mode -eq 'Plan') { $state | ConvertTo-Json -Depth 12; return }
New-Item -ItemType Directory -Path (Split-Path $StateFile -Parent) -Force | Out-Null
Invoke-VpnWindowsPlan $state $StateFile
Write-Output "ACTIVE: IPv4 tunnel policy; IPv6 blocked on guarded interfaces. Recovery state: $StateFile"
