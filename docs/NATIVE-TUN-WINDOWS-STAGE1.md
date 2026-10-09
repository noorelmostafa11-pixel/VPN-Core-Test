# Windows Native TUN — Experimental implementation and safety gates

Branch: \`feature/windows-native-tun-stage1\`. Production reference: \`main\` at \`90a1853114de3e4bcb3deed6747801c10bc5b370\`.
This work adds experimental in-process packet handling to the project-owned core. It does **not** enable a full-device VPN, change the existing CLI/SDK connection path, replace the Windows app, or remove the existing external tun2socks fallback.

## Implemented (source-level)

- \`src/native-wintun.hpp\`: dynamically loads Wintun by explicit absolute path, including \`WintunGetAdapterLUID\`. Loading alone creates no adapter.
- \`src/native-wintun-session.hpp\`: opt-in Wintun adapter/session RAII, bounded raw packet reads and constrained response injection. Its constructor has OS side effects, but the core's normal run path never constructs it. Worker lifetime must outlive adapter use.
- \`src/native-tun-packet.hpp\`: IPv4 TCP/UDP packet classifier with fragment/UDP443/IPv6 rejection. This is not a Windows firewall or an IP routing policy.
- \`src/native-tun-udp.hpp\`: 256-entry IPv4 UDP flow map, checksums, endpoint-bound replies, TTL.
- \`src/native-tun-udp-protocol.hpp\`: per-flow VLESS/VMess/Trojan UDP transports or Shadowsocks native encrypted UDP; requires protected sockets/bootstrap resolver and never switches to a direct unencrypted target path.
- \`src/native-tun-tcp.hpp\`: minimal TCP framing/sequence handshake, checksum and FIN/ACK tests.
- \`src/native-tun-tcp-reliable.hpp\`: experimental native in-order TCP ACK tracking, server-side send capacity, single in-flight segment, retransmissions and half-close. This is **not a complete TCP/IP stack**. Receive queue backpressure, out-of-order reassembly, congestion control, negotiated options and robust teardown still need implementation and tests.
- \`src/native-tun-tcp-socks.hpp\`: bounded TCP relay to **127.0.0.1**, speaking SOCKS5 to the core's already-running listener. The selected core protocol handles upstream encryption. The bridge fails closed without socket protector and resolver hooks. TCP loopback handshake may block a worker during upstream negotiation; asynchronous production scheduling is not implemented.
- \`src/native-tun-ip-pump.hpp\`: experimental single-reader Wintun TCP/UDP dispatch and response injection, compiled for Windows but **never instantiated by the normal core SDK/CLI**.
- \`src/native-windows-network-snapshot.hpp\`: read-only inventory of IPv4/IPv6 routes, adapter gateways and configured DNS servers; not enough to restore every DHCP/static DNS setting.
- \`src/native-network-rollback.hpp\`: in-memory scoped reverse-order undo journal with partial-operation compensation and retry of failed undo steps. No Windows route or DNS mutating calls are registered yet.

## Automated tests

The experimental \`Build Selected Core Target\` workflow runs Windows and Linux jobs automatically for this branch; it keeps \`main\` unchanged. The tests compile isolated packet, UDP, TCP, SOCKS, Wintun, route inventory and rollback modules.
- Confirmed earlier **Success** on Linux + Windows: run [37911094932](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/runs/37911094932), commit \`fbb697c4f37b3357ddf73378471550ca3292feef\` (before the newer TCP-SOCKS/combined pump changes).
- The current branch's new TCP SOCKS relay/combined pump/adapter LUID changes require a **fresh successful run at that exact commit**. Do not infer success from an older build.
- Local independent rollback tests passed with GCC and ASan/UBSan. None of these tests uses a live Wintun adapter or reconfigures real network routes.

## Blocking work before any real tunnel activation or Windows app integration

1. Harden the native TCP stack: bounded receive acceptance, backpressure before ACK, reassembly/reordering, ACK/window/FIN state, retransmissions, congestion behavior and lifecycle across all protocols. Prove a real TCP transfer with and without loss.
2. Add a public Windows native-TUN run/lifecycle API, dedicated owned I/O worker and a tested handshake with the already-running encrypted protocol engine.
3. Implement **Windows-owned** endpoint route pinning, DNS changes, IPv6 enforcement and kill switch as one transaction, including restoration of DHCP/static settings and error recovery. Inventory + generic rollback journal alone do not suffice.
4. Establish QUIC/UDP443 policy **before** full-device route activation; verify all traffic is captured/blocked with no unintended OS-side DNS or IPv6 fallback.
5. Pin/verify/distribute \`wintun.dll\`, validate required privileges/adapter ownership; test Connect/Disconnect and process termination/restart, leak tests, IPv4/IPv6 and DNS, and compare connection latency with the old app.
6. Perform Windows in-application integration and user-device acceptance tests; preserve the stable 0.4.11/tun2socks fallback until the new path has passed.

## Safety status

**NOT READY TO INTEGRATE.** The normal \`vpn_core_run_config\` entry point still uses its existing SOCKS5 path; the new Wintun pump is deliberately dormant. There is no activated default route, no DNS reconfiguration, no IPv6 change and no new kill switch in this branch. Passing CI verifies compilation and the covered local contracts, **not** a functional, leak-proof Windows VPN.
