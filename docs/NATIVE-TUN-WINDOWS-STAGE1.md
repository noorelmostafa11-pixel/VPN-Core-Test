# Windows Native TUN — Stage 1 (experimental)

Source branch: `feature/windows-native-tun-stage1`. Stable `main` remains unchanged.

## Implemented

- `src/native-tun-packet.hpp` provides a bounded IPv4 packet policy inspection function. It rejects malformed frames, IPv4 fragments, unsupported IP protocols, IPv6 (until explicitly implemented), and outbound UDP/443. This is only packet classification, **not** a complete firewall, data path or packet integrity proof.
- `src/native-wintun.hpp` loads Wintun exports from an explicit local absolute DLL path. Constructing the loader does not create an adapter or modify Windows network configuration. The caller must keep the loader alive while using any of its function pointers.
- `tests/native_tun_packet_probe.cpp` checks ordinary TCP, UDP/53, forbidden UDP/443 and invalid input.
- `tests/native_wintun_loader_probe.cpp` checks rejection of a relative DLL path without attempting to create an adapter.
- `src/native-wintun-session.hpp` adds an opt-in RAII wrapper for Wintun adapter creation, 4 MiB ring sessions, bounded reads, explicit packet injection, policy-drop counters and cooperative stop. Merely loading the core DOES NOT instantiate this wrapper.
- Windows `vpn-core.exe --check-native-tun <absolute-dll-path>` performs a read-only Wintun loader/export check and exits without creating an adapter, opening a Wintun session or modifying routes/DNS.
- The Windows loader probe also includes the session header to check it compiles. These checks do not exercise a live driver or establish a functioning VPN.
- The existing manually triggered `build-targets.yml` workflow now compiles and runs the probes when the corresponding Linux/Windows target is selected.

- `src/native-tun-udp-protocol.hpp` reuses existing `UdpTunnel` sessions for VLESS, VMess and Trojan; Shadowsocks uses its existing authenticated/native UDP codec and protected server socket. Each native flow has a separate protocol session, bound to its destination address and port. Socket-protection and bootstrap-resolver hooks are mandatory; there is no OS/direct fallback when they are absent.
- `src/native-tun-udp-pump.hpp` connects experimental Wintun packet reads, UDP flow mapping, project protocol sessions and authenticated response injection. TCP is explicitly rejected; the pump is not invoked by the public SDK or the CLI. Live routes must NOT be activated.
- `tests/native_tun_udp_protocol_probe.cpp` checks strict UDP endpoint identity and failure without protection hooks. It is included in Windows/Linux manual CI, but CI results have not been observed for this revision.

- `src/native-tun-udp.hpp` implements a 256-flow, 60-second IPv4 UDP request/response mapper. It validates IPv4 and nonzero UDP checksums, rejects UDP/443, IPv6 and fragments, exposes RFC 1928 IPv4 destination bytes, checks authenticated response endpoint identity and builds return IPv4/UDP packets with checksums.
- `src/native-wintun-session.hpp` now exposes `map_udp_request` and `inject_udp_response`; raw packet injection is private. The mapper does **not** connect to `UdpTunnel`, open sockets, or send traffic on its own.
- `tests/native_tun_udp_probe.cpp` covers valid request/reply, checksums, mismatched source/port, capacity, flow expiry, invalid UDP length, fragment and IPv6 rejection. The probe passed on local Linux GCC 14.2.0 with release flags and ASan/UBSan; Windows workflow coverage is wired but unrun.

## Not yet implemented — do not activate as a VPN

- No application-driven live adapter/session lifecycle or deployed packet read/write loop. The experimental RAII session class is implemented but is not invoked by the VPN core run path.
- No TCP stack or TCP stream reconstruction. The experimental UDP relay now calls existing core protocol transports, but it has no active application/SDK entry point and has not passed a real Windows Wintun/proxy/network test. The UDP path alone does not constitute a functional VPN.
- No VPN outbound endpoint bypass / route pinning / DNS leak safeguards / protected bootstrap inside a native path.
- No full-tunnel Windows route, DNS and IPv6 transaction with audited rollback and fail-closed kill switch.
- No active native TUN integration into `vpn_core_run_config`, no new SDK API, no replacement of the external tun2socks process. The in-core UDP pump is compiled but NOT activated by run_config. The Windows CLI has a separate read-only DLL check.
- No Windows build or live tunnel smoke test has yet been completed for this stage. Local packet policy and UDP codec probes passed on Linux GCC 14.2, including UDP AddressSanitizer/UndefinedBehaviorSanitizer; this is not an end-to-end production build or Windows driver test.

## Safety gates before enabling any real tunnel

1. Implement and test TCP/IP and UDP packet handling in isolation, covering malformed traffic, cancellation and lifecycle.
2. Map each accepted packet to the existing project-owned protocol sessions; never silently switch to direct outbound connections.
3. Use pinned physical routes for the remote VPN endpoint, with DNS fail-closed and IPv6 protections.
4. Create a session-owned adapter, and preserve/restore original interface settings on success, failure and cancellation.
5. Verify UDP/443 blocking happens **before** IPv4 routes are activated; classifier-only blocking is insufficient if other paths can bypass it.
6. Run Windows build, local loopback tests, real VPN tests, DNS/IPv6 leak checks and Connect/Disconnect regression tests. Keep the existing tun2socks path available for rollback.

## Running the manual checks

Choose **Build Selected Core Target** on this branch with target `windows` and/or `linux`. No workflow runs automatically on commit.

The tests exercise packet classification, local UDP packet/flow conversion, UDP transport hook/endpoint contract and loader validation only. A build or probe pass does **not** establish that native TUN works, that traffic is encrypted on a real path, or that system network routing is safe.
