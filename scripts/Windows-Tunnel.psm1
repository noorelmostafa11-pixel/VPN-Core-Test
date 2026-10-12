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

function Set-VpnDnsFamily([int]$Index,[string]$Family,[string[]]$Servers,[bool]$Automatic=$false) {
    $Servers=@($Servers | Where-Object { $_ })
    $familyName=if($Family -eq 'IPv6') { 'ipv6' } else { 'ipv4' }
    $netsh=Join-Path $env:SystemRoot 'System32\netsh.exe'
    $arguments=@('interface',$familyName,'set','dnsservers',"name=$Index")
    if($Automatic) { $arguments+='source=dhcp' }
    else {
        $arguments+='source=static'
        $first=if(@($Servers).Count -gt 0) { [string]$Servers[0] } else { 'none' }
        $arguments+=@("address=$first",'validate=no')
    }
    $output=& $netsh @arguments
    if($LASTEXITCODE -ne 0) { throw "DNS $Family configuration failed: $output" }
    if(!$Automatic) {
        for($i=1;$i -lt @($Servers).Count;$i++) {
            $output=& $netsh interface $familyName add dnsservers "name=$Index" "address=$($Servers[$i])" "index=$($i+1)" validate=no
            if($LASTEXITCODE -ne 0) { throw "DNS $Family configuration failed: $output" }
        }
    }
}
function Get-VpnWindowsOperations {
    return @{
        AddRoute = { param($r) New-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $r.Index -NextHop $r.NextHop -RouteMetric 1 -AddressFamily $r.Family -PolicyStore ActiveStore -ErrorAction Stop | Out-Null }
        RemoveRoute = { param($r) if (!(Test-VpnAdapterIdentity $r.Index $r.Guid)) { return }; Get-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $r.Index -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object NextHop -eq $r.NextHop | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
        AddAddress = { param($s)
            foreach ($a in $s.TunAddresses) {
                $canonical=[Net.IPAddress]::Parse($a.Address).ToString()
                New-NetIPAddress -InterfaceIndex $s.TunIndex -AddressFamily $a.Family -IPAddress $canonical -PrefixLength $a.Prefix -SkipAsSource $false -ErrorAction Stop | Out-Null
                # Route only after Windows can select this address as a source.
                $deadline=[DateTime]::UtcNow.AddSeconds(8)
                do {
                    $address=Get-NetIPAddress -InterfaceIndex $s.TunIndex -AddressFamily $a.Family -IPAddress $canonical -ErrorAction Stop
                    if ($address.AddressState -eq 'Preferred') { break }
                    if ($address.AddressState -in @('Duplicate','Invalid')) { throw "TUN $($a.Family) address is $($address.AddressState)" }
                    if ([DateTime]::UtcNow -ge $deadline) { throw "TUN $($a.Family) address did not become usable" }
                    Start-Sleep -Milliseconds 100
                } while ($true)
            }
        }
        RemoveAddress = { param($s)
            if (!(Test-VpnAdapterIdentity $s.TunIndex $s.TunGuid)) { return }
            foreach ($a in $s.TunAddresses) {
                $canonical=[Net.IPAddress]::Parse($a.Address).ToString()
                foreach($store in @('ActiveStore','PersistentStore')) {
                    Get-NetIPAddress -InterfaceIndex $s.TunIndex -AddressFamily $a.Family -IPAddress $canonical -PolicyStore $store -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
                }
            }
        }
        SetMetric = { param($s)
            foreach ($m in $s.TunMetrics) { Set-NetIPInterface -InterfaceIndex $s.TunIndex -AddressFamily $m.Family -AutomaticMetric Disabled -InterfaceMetric 1 -ErrorAction Stop }
        }
        RestoreMetric = { param($s)
            if (!(Test-VpnAdapterIdentity $s.TunIndex $s.TunGuid)) { return }
            foreach ($m in $s.TunMetrics) {
                if ($m.Automatic -eq 'Enabled') { Set-NetIPInterface -InterfaceIndex $s.TunIndex -AddressFamily $m.Family -AutomaticMetric Enabled -ErrorAction Stop }
                else { Set-NetIPInterface -InterfaceIndex $s.TunIndex -AddressFamily $m.Family -AutomaticMetric Disabled -InterfaceMetric $m.Value -ErrorAction Stop }
            }
        }
        SetDNS = { param($d,$servers)
            Set-VpnDnsFamily $d.Index $d.Family @($servers | Where-Object { $_ })
        }
        RestoreDNS = { param($d)
            if (!(Test-VpnAdapterIdentity $d.Index $d.Guid)) { return }
            Set-VpnDnsFamily $d.Index $d.Family @($d.Servers) (!$d.Static)
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
        foreach ($d in $State.DNS) {
            $servers=if($State.Schema -eq 'vpn-windows-session-v1'){@($State.DnsIPv4)}else{@($d.TargetServers)}
            & $Operations.SetDNS $d $servers
        }
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
    if ($State.Schema -eq 'vpn-windows-session-v1') {
        $State | Add-Member -NotePropertyName TunAddresses -NotePropertyValue @(@{Family='IPv4';Address=$State.TunAddress;Prefix=30}) -Force
        $State | Add-Member -NotePropertyName TunMetrics -NotePropertyValue @(@{Family='IPv4';Automatic=$State.TunMetric.Automatic;Value=$State.TunMetric.Value;DHCP=$State.TunMetric.DHCP}) -Force
        foreach ($d in $State.DNS) { $d | Add-Member -NotePropertyName Family -NotePropertyValue 'IPv4' -Force }
    } elseif ($State.Schema -ne 'vpn-windows-session-v2') { throw 'Unrecognized session state' }
    $errors = [System.Collections.Generic.List[string]]::new()
    # Restore while the physical-network guards are still enabled. If restoring
    # DNS/routes fails, retain the guard and state for an explicit recovery retry.
    foreach ($r in $State.Routes) { try { & $Operations.RemoveRoute $r } catch { $errors.Add('Route restoration failed') } }
    foreach ($d in $State.DNS) { try { & $Operations.RestoreDNS $d } catch { $errors.Add('DNS restoration failed') } }
    try { & $Operations.RemoveAddress $State } catch { $errors.Add('Address restoration failed') }
    # The app created this TUN adapter and removes it on stop. A metric restore
    # failure on this disposable adapter must not retain physical-network guards.
    try { & $Operations.RestoreMetric $State } catch { Write-Warning ('Session TUN metric restoration: ' + $_.Exception.Message) }
    try { & $Operations.FlushDNS } catch { $errors.Add('DNS cache restoration failed') }
    if ($errors.Count -gt 0) { throw ($errors -join '; ') }
    foreach ($r in $State.Rules) { try { & $Operations.RemoveRule $r } catch { $errors.Add('Firewall restoration failed') } }
    if ($errors.Count -gt 0) { throw ($errors -join '; ') }
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
}
Export-ModuleMember -Function Get-VpnBlockedIPv4Ranges,Get-VpnWindowsOperations,Invoke-VpnWindowsPlan,Restore-VpnWindowsPlan
