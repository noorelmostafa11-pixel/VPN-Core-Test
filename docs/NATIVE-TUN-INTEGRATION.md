# Native TUN integration (experimental branch)

Current development uses the pinned gVisor netstack inside the existing TLS
provider's Go runtime and the current C++ protocol engine. No packet forwarding
subprocess or alternate VPN engine is used. The stable core ABI 2 and proxy
entry points remain available. Only `--experimental-netstack` enables TUN ABI 1.

**Development checkpoint: OS device, policy, integration and performance gates
are running. Do not describe this checkout as production approved or a finished
device-test package until the corresponding CI/device reports are recorded.**

## C / C++ embedding

`src/core-api.h` documents `vpn_core_run_tun` and sized TUN options. Run on an
owned application worker, retain hooks/config/options until it returns, call
`vpn_core_stop`, join, then release original TUN descriptors. FD mode duplicates
the supplied FD and closes its copy. Nonblocking flags are shared, so callers
must perform no competing I/O. `vpn_core_tun_ready` means packet/device ready;
protocol connections authenticate independently per flow. SOCKS listen port is
zero in this mode. `vpn_core_bootstrap_targets` supplies JSON host/port metadata
without DNS I/O or credentials for desktop policy setup. Resolve every entry
before routing, include exact endpoint ports, and keep resolver/protection hooks
alive until the run has joined. The one-run lock is shared with all existing core entries.

Packet I/O does not establish protocol connections. Bounded joinable flow
workers own C++ protocol/TLS state. Serialized short packet ABI calls never
retain Go or C++ pointers. TCP applies bounded stream backpressure; UDP retains
record boundaries and counts newest-record drops on bounded queue overflow.
Failures abort only the affected flow, preserve the original causal reason,
and retain the TUN instead of falling back to unencrypted networking.

## Windows

Build with `scripts/Build.py --target windows --experimental-netstack` and
acquire signed Wintun using `scripts/Get-Wintun.py --build build/windows-amd64`.
The standalone `vpn-native-tun.exe` embeds the same core in its own process.
Run elevated with `--config`, absolute `--wintun`, and physical
`--uplink-index`. Original parser determines node host/port; DNS is resolved
before route activation, and protected sockets bind to the underlying interface.
Bootstrap metadata includes separate XHTTP download and configured ECH resolver
endpoints. The policy allows their exact IP/port union for this process only.
The persistent, owned WFP guard precedes full-tunnel routes/DNS. Adapter DNS is
link-scoped, never a global physical-adapter replacement. Ctrl+C requests stop
and joins before disconnect. On fatal error/crash the guard remains fail closed;
`--recover-network` explicitly removes only the application's WFP owner.
`--test-routes` is a controlled CI fixture mode, not the full-tunnel policy.

## Linux

`sdk/linux/native_tun.py` loads the experimental shared core in-process. It
requires root/CAP_NET_ADMIN, iproute2, nftables and systemd-resolved. Its mandatory
bootstrap host/port and physical interface describe the original node; it does
not rewrite the node URI. Route/DNS state belongs to an ephemeral `/dev/net/tun`
interface; no global resolver/default route is overwritten. The atomic owned
nftables table allows loopback, TUN, and marked node sockets at the configured
endpoint. Separate XHTTP download and ECH resolver endpoints are derived from
the same parsed configuration, pre-resolved, and admitted only for marked sockets.
The table remains after a crash; `--recover` removes only its marker.

## Android

`NativeCore.runTun` borrows an established VpnService FD and requires network
protection/bootstrap hooks. The integration source is in
`sdk/android/service/.../VpnCoreVpnService.java`. It adds both family defaults,
link DNS and addresses, pins socket/DNS operations to a non-VPN underlying
Network, and keeps the TUN across core failure or network loss. Reconnect joins
old core work before creating new sessions. Explicit Disconnect closes the FD.
Android's always-on **Block connections without VPN** must be enabled by the
user/system policy for fail-closed behavior across process death; an app alone
cannot impose this system setting. The experiment APK is a separate host and
its debug signature is unsuitable for production updates.

## Compatibility and evidence

Never rewrite input node URIs or weaken certificate/REALITY verification.
Compare against stable `0.4.11`, retain SOCKS and existing SDK APIs, and record
live node results separately from offline parser equality. Packet copy timings
are not end-to-end VPN throughput. Current OS tests use controlled encrypted
peers; physical Windows/Android devices remain a separate acceptance gate.
