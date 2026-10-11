# Optional host policy. Packet forwarding itself remains in the Go core.
Set-StrictMode -Version Latest

function ConvertTo-VpnIPv4Number([string]$Address) {
    $ip = [System.Net.IPAddress]::Parse($Address)
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'IPv4 address required' }
    $b = $ip.GetAddressBytes()
    return ([uint64]$b[0] * 16777216 + [uint64]$b[1] * 65536 + [uint64]$b[2] * 256 + [uint64]$b[3])
}
function ConvertFrom-VpnIPv4Number([uint64]$Value) {
    return '{0}.{1}.{2}.{3}' -f (($Value -shr 24) -band 255), (($Value -shr 16) -band 255), (($Value -shr 8) -band 255), ($Value -band 255)
}
function Get-VpnBlockedIPv4Ranges([string[]]$UpstreamIPv4) {
    # An explicit broad block beats an allow rule in Windows Firewall. Exclude
    # the upstream addresses from the block instead of adding ineffective allows.
    $cursor = [uint64]0
    foreach ($ip in @($UpstreamIPv4 | ForEach-Object { ConvertTo-VpnIPv4Number $_ } | Sort-Object -Unique)) {
        if ($ip -gt $cursor) { '{0}-{1}' -f (ConvertFrom-VpnIPv4Number $cursor), (ConvertFrom-VpnIPv4Number ($ip - 1)) }
        $cursor = $ip + 1
    }
    if ($cursor -le 4294967295) { '{0}-255.255.255.255' -f (ConvertFrom-VpnIPv4Number $cursor) }
}

function Save-VpnWindowsState($State, [string]$Path) {
    $temporary = $Path + '.new'
    $State | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-VpnWindowsOperations {
    return @{
        AddRoute = { param($r) New-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $r.Index -NextHop $r.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null }
        RemoveRoute = { param($r) if (!(Test-VpnAdapterIdentity $r.Index $r.Guid)) { return }; Get-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $r.Index -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object NextHop -eq $r.NextHop | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
        AddAddress = { param($s) New-NetIPAddress -InterfaceIndex $s.TunIndex -IPAddress $s.TunAddress -PrefixLength 30 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null }
        RemoveAddress = { param($s) if (!(Test-VpnAdapterIdentity $s.TunIndex $s.TunGuid)) { return }; Get-NetIPAddress -InterfaceIndex $s.TunIndex -IPAddress $s.TunAddress -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop }
        SetMetric = { param($s) Set-NetIPInterface -InterfaceIndex $s.TunIndex -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 1 -ErrorAction Stop }
        RestoreMetric = { param($s) if (!(Test-VpnAdapterIdentity $s.TunIndex $s.TunGuid)) { return }; Set-NetIPInterface -InterfaceIndex $s.TunIndex -AddressFamily IPv4 -AutomaticMetric $s.TunMetric.Automatic -InterfaceMetric $s.TunMetric.Value -Dhcp $s.TunMetric.DHCP -ErrorAction Stop }
        SetDNS = { param($d,$servers) $inputObject=Get-DnsClientServerAddress -InterfaceIndex $d.Index -AddressFamily IPv4 -ErrorAction Stop; Set-DnsClientServerAddress -InputObject $inputObject -ServerAddresses $servers -ErrorAction Stop }
        RestoreDNS = {
            param($d)
            if (!(Test-VpnAdapterIdentity $d.Index $d.Guid)) { return }
            $inputObject=Get-DnsClientServerAddress -InterfaceIndex $d.Index -AddressFamily IPv4 -ErrorAction Stop
            if ($d.Static) { Set-DnsClientServerAddress -InputObject $inputObject -ServerAddresses $d.Servers -ErrorAction Stop }
            else { Set-DnsClientServerAddress -InputObject $inputObject -ResetServerAddresses -ErrorAction Stop }
        }
        AddRule = {
            param($r)
            $rule=@{Name=$r.Name;DisplayName=$r.Name;Group=$r.Group;Direction='Outbound';Action='Block';Enabled='True';Profile='Any';InterfaceAlias=$r.Interfaces;RemoteAddress=$r.Addresses;Protocol=$r.Protocol;ErrorAction='Stop'}
            if (@($r.Ports).Count -gt 0) { $rule.RemotePort=$r.Ports }
            New-NetFirewallRule @rule | Out-Null
            $active=Get-NetFirewallRule -PolicyStore ActiveStore -Name $r.Name -ErrorAction Stop
            if ($active.Enabled -ne 'True' -or $active.Action -ne 'Block') { throw 'Local firewall guard is not active' }
        }
        RemoveRule = { param($r) Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop }
        FlushDNS = { Clear-DnsClientCache -ErrorAction Stop }
    }
}

function Test-VpnAdapterIdentity([int]$Index, [string]$Guid) {
    $adapter=Get-NetAdapter -IncludeHidden | Where-Object ifIndex -eq $Index
    return ($null -ne $adapter -and [string]$adapter.InterfaceGuid -eq $Guid)
}

function Invoke-VpnWindowsPlan($State, [string]$Path, [hashtable]$Operations = (Get-VpnWindowsOperations)) {
    if (Test-Path -LiteralPath $Path) { throw 'A session state already exists; restore that session first' }
    $State.Phase='Applying'
    Save-VpnWindowsState $State $Path # recovery plan exists before the first mutation
    try {
        foreach ($r in $State.Rules) { & $Operations.AddRule $r }
        & $Operations.AddAddress $State
        & $Operations.SetMetric $State
        foreach ($r in $State.Routes) { & $Operations.AddRoute $r }
        foreach ($d in $State.DNS) { & $Operations.SetDNS $d $State.DnsIPv4 }
        & $Operations.FlushDNS
        $State.Phase='Active'
        Save-VpnWindowsState $State $Path
    } catch {
        $original = $_
        try { Restore-VpnWindowsPlan $State $Path $Operations } catch { Write-Warning "Recovery is incomplete; retry Restore with $Path" }
        throw $original
    }
}

function Restore-VpnWindowsPlan($State, [string]$Path, [hashtable]$Operations = (Get-VpnWindowsOperations)) {
    if ($State.Schema -ne 'vpn-windows-session-v1') { throw 'Unrecognized session state' }
    $errors = [System.Collections.Generic.List[string]]::new()
    # Restore while the physical-network guards are still enabled. If restoring
    # DNS/routes fails, retain the guard and state for an explicit recovery retry.
    foreach ($r in $State.Routes) { try { & $Operations.RemoveRoute $r } catch { $errors.Add('Route restoration failed') } }
    foreach ($d in $State.DNS) { try { & $Operations.RestoreDNS $d } catch { $errors.Add('DNS restoration failed') } }
    try { & $Operations.RemoveAddress $State } catch { $errors.Add('Address restoration failed') }
    try { & $Operations.RestoreMetric $State } catch { $errors.Add('Metric restoration failed') }
    try { & $Operations.FlushDNS } catch { $errors.Add('DNS cache restoration failed') }
    if ($errors.Count -gt 0) { throw ($errors -join '; ') }
    foreach ($r in $State.Rules) { try { & $Operations.RemoveRule $r } catch { $errors.Add('Firewall restoration failed') } }
    if ($errors.Count -gt 0) { throw ($errors -join '; ') }
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
}
Export-ModuleMember -Function Get-VpnBlockedIPv4Ranges,Get-VpnWindowsOperations,Invoke-VpnWindowsPlan,Restore-VpnWindowsPlan
