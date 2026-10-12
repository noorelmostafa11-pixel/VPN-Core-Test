[CmdletBinding()]
param(
    [ValidateSet('Plan','Apply','Restore')][string]$Mode='Plan',
    [string]$TunName='VPN-Core',
    [string]$PhysicalInterfaceAlias='',
    [string[]]$UpstreamIPv4=@(),
    [string[]]$UpstreamIPv6=@(),
    [ValidateRange(1,65535)][int]$UpstreamPort=443,
    [string[]]$DnsIPv4=@('127.0.0.1'),
    [string[]]$DnsIPv6=@(),
    [switch]$FirewallGuard,
    [string]$TunAddress='10.248.231.1',
    [string]$TunAddressIPv6='fd48:248:231::1',
    [Parameter(Mandatory=$true)][string]$StateFile
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Windows-Tunnel.psm1') -Force
if ($Mode -ne 'Plan') {
    $taskPrincipal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$taskPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Apply/Restore requires Administrator.' }
}
$StateFile=[IO.Path]::GetFullPath($StateFile)
if ($Mode -eq 'Restore') {
    $state=Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    Restore-VpnWindowsPlan $state $StateFile
    Write-Output 'RESTORED: IPv4/IPv6 routes, addresses, metrics and DNS; session firewall rules removed.'
    return
}
if (@($UpstreamIPv4).Count + @($UpstreamIPv6).Count -eq 0) { throw 'An upstream IP address is required.' }
foreach($address in @($UpstreamIPv4)+@($TunAddress)) {
    $ip=[Net.IPAddress]::Parse($address)
    if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or [Net.IPAddress]::IsLoopback($ip) -or $ip.GetAddressBytes()[0] -eq 0 -or $ip.GetAddressBytes()[0] -ge 224) { throw 'Invalid unicast IPv4 address.' }
}
foreach($address in @($DnsIPv4)) {
    $ip=[Net.IPAddress]::Parse($address)
    if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.GetAddressBytes()[0] -eq 0 -or $ip.GetAddressBytes()[0] -ge 224) { throw 'Invalid DNS IPv4 address.' }
}
foreach($address in @($UpstreamIPv6)+@($TunAddressIPv6)) {
    $ip=[Net.IPAddress]::Parse($address)
    if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6 -or [Net.IPAddress]::IsLoopback($ip) -or $ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.Equals([Net.IPAddress]::IPv6Any)) { throw 'Invalid unicast IPv6 address.' }
}
foreach($address in @($DnsIPv6)) {
    $ip=[Net.IPAddress]::Parse($address)
    if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6 -or $ip.IsIPv6Multicast -or $ip.Equals([Net.IPAddress]::IPv6Any)){throw 'Invalid DNS IPv6 address.'}
}
$tun=Get-NetAdapter -Name $TunName -ErrorAction Stop
if(@($tun).Count -ne 1 -or $tun.Status -ne 'Up') { throw 'The native Wintun adapter is not Up.' }
# Hidden WAN miniports report Up but are not usable firewall interface aliases.
# New-NetFirewallRule -InterfaceAlias accepts literal names, not wildcard escapes.
$interfaces=@(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.ifIndex -ne $tun.ifIndex })
if($PhysicalInterfaceAlias){$interfaces=@($interfaces|Where-Object Name -eq $PhysicalInterfaceAlias)}
if($interfaces.Count -eq 0) { throw 'No active underlying interfaces.' }
$indexes=@($interfaces | ForEach-Object { [int]$_.ifIndex })
$routes=@()
foreach($family in @('IPv4','IPv6')) {
    $upstream=if($family -eq 'IPv4') { @($UpstreamIPv4) } else { @($UpstreamIPv6) }
    if($upstream.Count -eq 0) { continue }
    $default=if($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
    $zero=if($family -eq 'IPv4') { '0.0.0.0' } else { '::' }
    $defaults=@(Get-NetRoute -AddressFamily $family -DestinationPrefix $default -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -in $indexes -and $_.NextHop -ne $zero })
    $route=$defaults | Sort-Object @{Expression={ $_.RouteMetric+(Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily $family).InterfaceMetric }} | Select-Object -First 1
    if(!$route) { throw "A physical $family route is required for this upstream." }
    $physical=$interfaces | Where-Object ifIndex -eq $route.InterfaceIndex
    $bits=if($family -eq 'IPv4') { 32 } else { 128 }
    foreach($ip in @($upstream | Sort-Object -Unique)) { $routes+=@{Prefix="$ip/$bits";Family=$family;Index=[int]$route.InterfaceIndex;Guid=[string]$physical.InterfaceGuid;NextHop=[string]$route.NextHop} }
}
foreach($prefix in @('0.0.0.0/1','128.0.0.0/1')) { $routes+=@{Prefix=$prefix;Family='IPv4';Index=[int]$tun.ifIndex;Guid=[string]$tun.InterfaceGuid;NextHop='0.0.0.0'} }
foreach($prefix in @('::/1','8000::/1')) { $routes+=@{Prefix=$prefix;Family='IPv6';Index=[int]$tun.ifIndex;Guid=[string]$tun.InterfaceGuid;NextHop='::'} }
foreach($r in $routes) {
    if(Get-NetRoute -AddressFamily $r.Family -DestinationPrefix $r.Prefix -InterfaceIndex $r.Index -PolicyStore ActiveStore -ErrorAction SilentlyContinue) { throw 'A planned route already exists; restore its owner first.' }
}
$addresses=@(@{Family='IPv4';Address=$TunAddress;Prefix=30},@{Family='IPv6';Address=$TunAddressIPv6;Prefix=64})
foreach($a in $addresses) { if(Get-NetIPAddress -IPAddress $a.Address -ErrorAction SilentlyContinue) { throw 'A planned TUN address is already in use.' } }
$metrics=@()
foreach($family in @('IPv4','IPv6')) {
    $metric=Get-NetIPInterface -InterfaceIndex $tun.ifIndex -AddressFamily $family -ErrorAction Stop
    $metrics+=@{Family=$family;Automatic=[string]$metric.AutomaticMetric;Value=[int]$metric.InterfaceMetric;DHCP=[string]$metric.Dhcp}
}
$dns=@()
foreach($a in @($interfaces)+@($tun)) {
    foreach($family in @('IPv4','IPv6')) {
        # DNS queries for both A and AAAA work over IPv4. Do not configure
        # unusable IPv6 resolvers or inactive IPv6 bindings.
        if (!(Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily $family -ErrorAction SilentlyContinue)) { continue }
        $inputObject=Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily $family -ErrorAction SilentlyContinue
        if(!$inputObject) { if($a.ifIndex -eq $tun.ifIndex) { throw "Wintun $family DNS registration is not ready." }; continue }
        $tcpip=if($family -eq 'IPv4') { 'Tcpip' } else { 'Tcpip6' }
        $registry=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$tcpip+'\Parameters\Interfaces\'+([Guid]$a.InterfaceGuid).ToString('B')) -ErrorAction SilentlyContinue
        $static=if($registry) { $registry.PSObject.Properties['NameServer'] } else { $null }
        $servers=@()
        # Static 'none' can fall back to DHCP DNS on Windows. Set the owned
        # loopback bridge explicitly on every active IPv4 interface instead.
        if($family -eq 'IPv4') { $servers=@($DnsIPv4) }
        elseif(@($DnsIPv6).Count -gt 0) { $servers=@($DnsIPv6) }
        $dns+=@{Index=[int]$a.ifIndex;Guid=[string]$a.InterfaceGuid;Family=$family;Static=($null -ne $static -and ![string]::IsNullOrWhiteSpace([string]$static.Value));Servers=@($inputObject.ServerAddresses);TargetServers=$servers}
    }
}
$group='VPN-Core-Session-'+[Guid]::NewGuid().ToString('N')
$aliases=@($interfaces | ForEach-Object { [string]$_.Name })
$rules=@()
# IPv6 is routed into TUN. There is no blanket IPv6 block.
if($FirewallGuard -and @($UpstreamIPv4).Count -gt 0) {
    if(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object Enabled -ne 'True') { throw 'Windows Firewall must be enabled for the IPv4 guard.' }
    $rules+=@{Name=$group+'-IPv4';Group=$group;Interfaces=$aliases;Addresses=@(Get-VpnBlockedIPv4Ranges $UpstreamIPv4);Protocol='Any';Ports=@()}
    $ports=@()
    if($UpstreamPort -gt 1) { $ports+=('1-'+($UpstreamPort-1)) }
    if($UpstreamPort -lt 65535) { $ports+=(($UpstreamPort+1).ToString()+'-65535') }
    foreach($protocol in @('TCP','UDP')) { $rules+=@{Name=$group+'-'+$protocol;Group=$group;Interfaces=$aliases;Addresses=@($UpstreamIPv4);Protocol=$protocol;Ports=$ports} }
}
$state=@{Schema='vpn-windows-session-v2';Phase='Plan';Group=$group;TunIndex=[int]$tun.ifIndex;TunGuid=[string]$tun.InterfaceGuid;TunAddresses=$addresses;TunMetrics=$metrics;DNS=$dns;Routes=$routes;Rules=$rules}
if($Mode -eq 'Plan') { $state | ConvertTo-Json -Depth 12; return }
New-Item -ItemType Directory -Path (Split-Path $StateFile -Parent) -Force | Out-Null
Invoke-VpnWindowsPlan $state $StateFile
Write-Output "ACTIVE: IPv4 and IPv6 tunnel routing. Recovery state: $StateFile"
