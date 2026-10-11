# Optional Windows IPv4 tunnel policy

The Go core forwards packets; `--tun` alone does not enforce machine routing,
DNS selection or a firewall policy. The separate 2026-10-11 Windows report
demonstrated real Wintun TCP/UDP forwarding, and also physical-interface DNS
traffic while only routes had been configured manually.

`Set-Windows-Tunnel.ps1` supplies an optional host policy. Run the native core
first and confirm SOCKS connectivity with your node. Use a node with a **literal
IPv4 upstream**, and supply every upstream IP (including an alternate XHTTP
download endpoint). This helper assumes one upstream port for those addresses.
Hostname bootstrap, changing server IPs and IPv6 upstreams need an application
that uses the Go SDK's physical-network resolver/socket hooks.

In an Administrator PowerShell window, preview the read-only plan:

```powershell
.\vpn-core.exe --config node.ini --tun VPN-Core --tun-only
# A second Administrator window; replace the documentation address with your server.
.\Set-Windows-Tunnel.ps1 -Mode Plan -TunName VPN-Core -UpstreamIPv4 192.0.2.10 -UpstreamPort 443
.\Set-Windows-Tunnel.ps1 -Mode Apply -TunName VPN-Core -UpstreamIPv4 192.0.2.10 -UpstreamPort 443
```

Apply performs the following transaction:

- Saves recovery state before changing the network.
- Adds explicit outbound block rules on the current active underlying adapters
  for IPv4 destinations outside the upstream allowlist, and IPv6 destinations.
  On upstream IPs, TCP/UDP ports other than the configured upstream port are blocked.
- Assigns the TUN address, sets its IPv4 metric, adds upstream `/32` bypasses and
  two `/1` tunnel routes. The original `/0` route is retained.
- Selects the configured IPv4 DNS servers on TUN and underlying interfaces,
  flushing the resolver cache. DNS to those servers follows the tunnel routes;
  sending it directly over guarded adapters is blocked.

This policy intentionally blocks physical IPv6 rather than claiming IPv6
forwarding. Core packet forwarding itself supports IPv6. The default DNS servers
are `1.1.1.1` and `1.0.0.1`; use `-DnsIPv4` to choose others. This is an IPv4
session policy, not a production VPN service: new adapters or changed upstream
addresses need a new plan. It blocks physical LAN traffic and DHCP renewal during
the session. It permits the upstream address/port on the guarded interfaces,
including traffic from other processes to that same endpoint. Existing company
policies or other VPNs can affect the result.

Windows gives explicit firewall blocks precedence over conflicting allows, so
the helper excludes upstream addresses from block ranges rather than relying on
an allow rule overriding a broad block. See [Microsoft's rule precedence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).
The DNS operation preserves each interface's original static/DHCP mode; see
[Microsoft's DNS configuration API](https://learn.microsoft.com/en-us/powershell/module/dnsclient/set-dnsclientserveraddress?view=windowsserver2025-ps).

Restore before ending the session:

```powershell
.\Set-Windows-Tunnel.ps1 -Mode Restore
```

The default state is `%ProgramData%\VPN-Core\windows-session.json`; a custom
`-StateFile` must be used consistently. Restore removes the session's routes and
address, restores IPv4 DNS mode and interface metric, then removes only its named
firewall rules. Adapter GUIDs prevent restoration onto a different adapter that
reused an interface index. If restoration fails, the file and firewall guard are
retained for a recovery retry. If the core or shell crashes, the guard remains
until explicit Restore. Do not delete the state file to recover connectivity.

Verified here: syntax and injected transaction failures, duplicate prevention,
original DNS mode restoration, guard retention on failed restore and recovery
retry. The current execution session cannot apply privileged networking changes.
The new policy still needs a real PktMon test on your Windows host: confirm HTTPS
and UDP inside TUN, absence of direct DNS and out-of-allowlist Wi-Fi packets, and
blocked direct traffic after stopping the core. A successful route lookup alone
does not establish leak protection.
