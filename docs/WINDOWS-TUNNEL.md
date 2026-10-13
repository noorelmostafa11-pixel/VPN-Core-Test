# Windows Native TUN

Run PowerShell as Administrator in the extracted Windows package:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Run-Native-Tunnel.ps1 -Config .\node.ini
```

The launcher preserves the original node URI, starts the single Go executable
with Wintun and its own local DNS, and configures the Windows interface. DNS
uses HTTPS/TCP443 through the selected node. No Windows application, Xray,
sing-box, C++ engine or tun2socks is started.

IPv4 is preferred while IPv6 stays supported. The launcher selects TCP mode for
blocked upstream UDP: native UDP/443 is rejected immediately and DNS HTTPS/SVCB
hints are suppressed. Other UDP support is retained. Native TCP/UDP DNS is
intercepted in Go; local UDP/TCP listeners serve Windows DNS clients.

Press Ctrl+C to stop. Captured DNS mode/servers and owned routes/addresses are
restored before stopping the owned core. An independent watcher restores the
transaction after unexpected parent/core exit. No blanket IPv6 firewall block
is installed. Wintun does not create an official Windows VPN profile or badge.

Default recovery state: %LOCALAPPDATA%\VPN-Go-Core\network-session.json.
Keep that file if restoration fails, and run as Administrator:

```powershell
.\Set-Windows-Tunnel.ps1 -Mode Restore -StateFile "$env:LOCALAPPDATA\VPN-Go-Core\network-session.json"
```

The lower-level host policy has read-only Plan, transactional Apply and Restore.
Specify TunName, resolved UpstreamIPv4/UpstreamIPv6 and StateFile. It waits for
usable addresses, installs physical bypasses and split routes, and registers
loopback DNS on active interfaces. Restore verifies interface identity. Legacy
v1 states remain supported; new states use v2. Firewall guards are optional.

Windows Internet acceptance covers two VLESS REALITY nodes and three HTTPS
sites each, with headless Chrome using default DNS/QUIC and no proxy/IP/host/TLS
overrides, native IPv6-addressed requests recovered through IPv4, and DNS rollback.
This does not claim IPv6 WAN egress or real Internet testing of every carrier.
Independent wire tests protect protocol compatibility; cross-builds verify
compilation, not Internet access on platforms without a local test device.
