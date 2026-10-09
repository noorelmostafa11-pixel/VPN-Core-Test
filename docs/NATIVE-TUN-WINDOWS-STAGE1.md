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

## Not yet implemented — do not activate as a VPN

- No application-driven live adapter/session lifecycle or deployed packet read/write loop. The experimental RAII session class is implemented but is not invoked by the VPN core run path.
- No TCP/IP stack, UDP NAT/session mapping, TCP stream reconstruction, end-to-end checksums or response generation. Raw packet injection in the wrapper alone is NOT a VPN response path.
- No VPN outbound endpoint bypass / route pinning / DNS leak safeguards / protected bootstrap inside a native path.
- No full-tunnel Windows route, DNS and IPv6 transaction with audited rollback and fail-closed kill switch.
- No active native TUN integration into `vpn_core_run_config`, no new SDK API, no replacement of the external tun2socks process. The Windows CLI has a separate read-only DLL check.
- No Windows build or live tunnel smoke test has yet been completed for this stage. A local GCC 14.2 reproduction of the packet-policy probe passed with AddressSanitizer and UndefinedBehaviorSanitizer; it is not an end-to-end production build or a Windows driver test.

## Safety gates before enabling any real tunnel

1. Implement and test TCP/IP and UDP packet handling in isolation, covering malformed traffic, cancellation and lifecycle.
2. Map each accepted packet to the existing project-owned protocol sessions; never silently switch to direct outbound connections.
3. Use pinned physical routes for the remote VPN endpoint, with DNS fail-closed and IPv6 protections.
4. Create a session-owned adapter, and preserve/restore original interface settings on success, failure and cancellation.
5. Verify UDP/443 blocking happens **before** IPv4 routes are activated; classifier-only blocking is insufficient if other paths can bypass it.
6. Run Windows build, local loopback tests, real VPN tests, DNS/IPv6 leak checks and Connect/Disconnect regression tests. Keep the existing tun2socks path available for rollback.

## Running the manual checks

Choose **Build Selected Core Target** on this branch with target `windows` and/or `linux`. No workflow runs automatically on commit.

The tests exercise packet classification and loader validation only; passing them does **not** establish that native TUN works, that traffic is encrypted, or that network routing is safe.
