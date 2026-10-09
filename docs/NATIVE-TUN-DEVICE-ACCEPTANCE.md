# Physical-device acceptance for the experiment

Use the three trial ZIPs emitted only after the three integration jobs pass.
Each includes matching source, binary hashes, build provenance, SDK/source
integration, and machine-readable controlled-test/performance evidence.
This is experimental acceptance, not production security/performance approval.

## Windows x64

Requires Windows 10 build 19041+ or Windows 11 and elevated PowerShell.
Extract the complete ZIP; keep every Core DLL beside the executable. Create
node.ini with one unchanged original URI:

    node_uri=<original URI>

From the extracted folder:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Core\Start-Native-Tun.ps1 -ConfigPath .\node.ini

Ctrl+C disconnects and joins. After an intentional crash or fatal failure:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Core\Start-Native-Tun.ps1 -Recover

Only the application's WFP owner is removed. Never disable all firewall rules.
Return to the original proxy path after stop/recovery:

    .\Core\vpn-core.exe --config .\node.ini

Test wired and Wi-Fi uplinks, IPv4-only and native IPv6, name-based nodes,
separate XHTTP download endpoints/ECH, repeated connect/disconnect, suspend,
network changes, forced process termination and explicit recovery. Verify DNS
and IPv6 cannot escape via the physical interface while the guard is active.
Compare the original 2,894-node private corpus with stable 0.4.11 under identical
connection deadlines/security rules. Retain originals and report each node ID;
offline parser equality is not live connection success.

## Android

Install vpn-core-native-tun-experiment.apk, enter the unchanged URI, approve
system VPN access and Connect. Test HTTPS connection performs an authenticated
HTTPS request with the platform's certificate checks. Disconnect explicitly.
The APK uses a fresh debug signing key per build; uninstall the old experimental
APK before installing this one. The four-ABI AAR is for embedding; service and
manifest integration source are supplied in SDK/android.

Enable Android always-on VPN and **Block connections without VPN** for protection
across process death. The app does not silently impose this system setting.
Test Wi-Fi/mobile transitions, IPv4/IPv6/dual-stack, private DNS settings, screen
off/Doze, loss and return of connectivity, process death with lockdown, VPN
permission revoke, repeated reconnect, and original-node compatibility.
Measure battery, CPU/PSS/RSS and speed on ARM devices; x86_64 emulator results
cannot certify ARM runtime or phone throughput.

## Linux x86_64

Requires root/CAP_NET_ADMIN, Python 3.10+, iproute2, nftables and systemd-resolved.
Use the original host and port; the host validates both against the parser and
derives additional configured bootstrap endpoints before activating routes.

    sudo python3 SDK/linux/native_tun.py --build Core --config node.ini --node-host ORIGINAL_HOST --node-port ORIGINAL_PORT --uplink PHYSICAL_INTERFACE

Ctrl+C disconnects. Explicit owned-policy recovery after a crash:

    sudo python3 SDK/linux/native_tun.py --recover

Legacy proxy after stopping/recovering:

    ./Core/vpn-core --config node.ini

A different DNS manager requires an owned link-specific integration; the host
fails startup instead of replacing global DNS or skipping protection.

## Record for each device

Record OS/device/CPU, package source SHA, original node ID, protocol/transport,
IP family, stable and experimental pass/fail, first causal failure, repeated
transfer hashes, speed/RTT, CPU/memory, network-change behavior, and owned-state
cleanup. Do not publish node credentials or private URI files in GitHub logs.

Controlled CI covers encrypted fixtures and both IP families inside the tunnel.
Windows physical IPv6 egress and Android mobile/vendor battery behavior require
the physical-device checks above. The bounded native resolver leases are drained
before Stop returns; a legacy Android system DNS callback may delay that join.
Do not close a borrowed FD or release hooks early to force a faster Stop.
