# Native TUN hardening after d96679c

This work continues the existing in-process gVisor/C++ integration. It does not
replace the parser, protocol engine, transports, SDK ABI, JNI or OS adapters.
The development branch is `feature/windows-native-tun-stage1`. Stable 0.4.11
and `main` remain unchanged. Production approval remains conditional on final
performance/security review and physical-device acceptance.

## Changes

| Area | Files | Result |
| --- | --- | --- |
| Foreign buffer ownership | `tls-provider/netstack.go`, `src/netstack-provider.hpp` | Remove intermediate `C.GoBytes`/flattening/scratch copies. Pinned endpoints copy into owned storage synchronously before returning. Packet references survive undersized output retries and are released on consumption/close. |
| Device packet I/O | `src/native-tun-device.hpp`, `src/main.cpp` | Wintun ring memory is borrowed only during synchronous injection, with release on success/exception. Linux/Android input and output use bounded reusable storage instead of per-packet allocation/zero-fill. |
| Flow shutdown/readiness | `src/netstack-core.hpp`, `src/udp-relay.hpp` | Drain upload before releasing a TCP flow after remote half-close. Carrier progress avoids artificial idle sleeps. Windows raw TCP/UDP workers use owned Winsock readiness events; asynchronous providers keep their bounded timer path. |
| Managed lifecycle | `sdk/native/tun_host.py` | One managed host owns startup/Stop/event draining until join. Stop on a completed host cannot stop a later host; timeout keeps descriptor/hook/run ownership alive. |
| Fail-closed recovery | `sdk/linux/native_tun.py` | Keep the owned firewall after route/DNS setup failure even if core Stop succeeds. Recovery requires exact table family/name/ownership comment and refuses failed inspection. |
| Observability | `tls-provider/netstack.go`, `src/netstack-core.hpp` | Add admission, UDP receive-buffer, link-output and transport drop counters without increasing queue sizes or changing pinned congestion behavior. |
| Regression coverage | `tests/test_netstack_abi.py`, `tls-provider/netstack_test.go`, `tests/test_native_tun_runtime.py`, `tests/native_half_close_peer.go`, `tests/test_native_tun_policy_lifecycle.py` | Verify foreign-memory lifetimes, split packet views, undersized retries, checksums, TCP send shutdown, queue limits, cleanup, managed ownership, TLS 1.3 upload draining and firewall failure/recovery decisions. |
| Measurement | `scripts/Benchmark-Netstack-ABI.py`, `scripts/Benchmark-Local-Native-Tun.py`, `scripts/Native-Tun-Benchmark-Worker.py`, `tests/native_tun_client.py` | Reproducible packet ABI and equivalent-load comparison; explicit CPU/RSS sampling inside the measured process. Synthetic client memory/retransmission bounds and measured retransmissions remain visible. |

The pinned gVisor version remains `89a5d21be8f0`. The legacy SOCKS and SDK paths,
original URI parser, TLS/REALITY authentication and certificate rejection are
unchanged. Native worker creation never runs on the device packet read loop.
The Windows event design follows the documented Winsock FD_READ/FD_WRITE
reenabling semantics; no global timer resolution is changed.

## Verification and scope

The evidence report supplied with the trial package identifies the exact commit,
binary hashes, job URLs and measurements actually completed. A previous green
run for d96679c is baseline evidence, not proof for modified code.

Local Linux verification includes encrypted packet/core cases (85 subcases),
managed runtime/FD tests, packet ABI ownership/limit tests, mocked policy
transaction tests, legacy UDP/SDK and bootstrap tests, Go race tests, and 32
post-stability resource cleanup cycles. The independent TLS 1.3 half-close test
sends a verified 1 MiB upload against a deliberately slow reader: d96679c loses
pending upload and the hardened core completes its byte count/hash.

The original private 2,894 URI file is unchanged (SHA256
`9d3d741ba31d89f1de6742edfa70dcf973154315ae4cd11fc94771b03687b493`). Offline
inspection records/node IDs match stable 0.4.11 exactly. This does not claim
that any public/private node connected during the local test.

The local environment has no CAP_NET_ADMIN, /dev/net/tun, Windows runtime or
Android emulator. Its borrowed-FD benchmark measures gVisor/C++ plus a bounded
Python TCP application, not Wintun/OS TCP/WAN throughput. Four exported ABI
calls per UDP exchange include Python/ctypes and stack work, so they are not a
pure language-call latency measurement. Go heap allocation deltas exclude the
controller. Native OS transfer, routing/policy, Android emulator and desktop
performance coverage comes from completed GitHub integration jobs.

## Build and integration

Use the existing pinned toolchains in [BUILDING.md](BUILDING.md). For a clean
checkout, build the optional packet engine explicitly:

```sh
python scripts/Build.py --target linux --experimental-netstack --build-tests --require-clean
python scripts/Build.py --target windows --experimental-netstack --build-tests --require-clean
python scripts/Get-Wintun.py --build build/windows-amd64
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  python scripts/Build.py --target android --abi "$abi" --experimental-netstack --require-clean
done
```

Android builds require the pinned NDK/JDK/SDK. Refer to
[NATIVE-TUN-INTEGRATION.md](NATIVE-TUN-INTEGRATION.md) for C ABI/JNI lifecycle,
Wintun, /dev/net/tun and VpnService FD ownership, bootstrap endpoints, DNS,
kill switch and explicit recovery. Integration into the original applications
is left to their owners. Disconnect and join before activating the legacy
SOCKS/SDK fallback; recover an owned persistent guard explicitly after a fatal
failure. Never release hooks/FD ownership after a Stop timeout.

## Reproduce local checks

Install `tests/requirements.txt`, put pinned Go on PATH, and set
`PYTHONPATH=tests`, `VPN_NATIVE_BUILD` and `VPN_CORE_TEST_BINARY` to the exact
built directory/executable. Then:

```sh
(cd tls-provider && go test -race -tags=netstack -mod=vendor .)
python -m unittest -v test_native_tun_encrypted test_native_tun_runtime test_netstack_abi test_native_tun_policy_lifecycle test_udp_sdk test_native_tun_bootstrap
python scripts/Test-Netstack-Compatibility.py --build build/linux-amd64 --output evidence/packet
python scripts/Benchmark-Netstack-ABI.py --build build/linux-amd64 --output evidence/abi.json
```

`Benchmark-Local-Native-Tun.py` accepts clean stable, d96679c baseline and
candidate build directories. The OS benchmark and device/policy scripts require
an isolated privileged runner; do not route a normal development machine into
a loopback test fixture. GitHub workflows contain the controlled OS setup.

## Final acceptance on physical devices

- Windows x64: real Wintun throughput/RTT/CPU, idle/resume, reconnect/cancel,
  long-running Handle/thread/socket counts, IPv6 uplinks, DNS and crash recovery.
- Android ARM phone: JNI FD ownership, VpnService permission/protect ordering,
  always-on/lockdown behavior, background/Doze/network changes, battery and memory.
- Unchanged private 2,894 node regression and all targeted failed nodes against
  the same security checks and connection deadline. No node support claims are
  inferred solely from parser equality or controlled fixture success.
- Packet captures during startup, failure, disconnect and process crash for DNS,
  IPv6 and protected bootstrap endpoints. Confirm intentional owned recovery.
- Production performance/security approval; compare lwIP only if a measured
  gVisor problem justifies it, with architecture approval first.

## Completed evidence (2026-10-10)

Production code is commit `5cde0c730b4d9452c4639b230570e027cc8fcf56`.
All three workflows succeeded:

- [Build targets](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/runs/38012343621)
- [Packet compatibility](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/runs/38012350647)
- [Three-OS integration, performance and verified packages](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/runs/38012345710)

The integration report confirms 72,767 public inventory inspection records
match 0.4.11. The local private 2,894-file comparison also matches exactly.
Windows/Linux ran actual native adapters and policy recovery tests; Android
ran VpnService on the x86_64 emulator after building all four ABIs. This does
not verify ARM phones or a physical Windows laptop.

Controlled OS median measurements (three rotated rounds, verified 8 MiB echo):

| System | Transport | Stable SOCKS Mbit/s | Native TUN Mbit/s | Stable RTT p50 ms | Native RTT p50 ms | Stable CPU s | Native CPU s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Windows | raw TLS | 178.96 | 119.41 | 0.568 | 1.039 | 0.094 | 0.984 |
| Windows | WebSocket TLS | 64.16 | 53.69 | 1.359 | 1.203 | 0.312 | 1.062 |
| Linux | raw TLS | 111.72 | 132.51 | 1.212 | 2.309 | 0.110 | 0.260 |
| Linux | WebSocket TLS | 96.72 | 97.93 | 82.970 | 83.528 | 0.280 | 0.720 |
| Android emulator | raw TLS | 62.02 | 58.23 | 1.752 | 3.461 | 0.491 | 0.915 |
| Android emulator | WebSocket TLS | 52.70 | 51.07 | 44.003 | 44.467 | 0.703 | 1.323 |

These compare packet-free SOCKS against full TUN, not identical engine work.
CPU covers the measured process, including host/runtime threads. Android has
system background VPN traffic. OS socket scheduling/Nagle behavior affects
RTT, particularly the local Linux WebSocket fixture.

The earlier d96679c integration run was
[37955881917](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/runs/37955881917).
Its Windows native median RTT was 2.097 ms raw / 2.229 ms WebSocket versus
1.039 / 1.203 ms now. Absolute throughput was 130.31 / 82.65 Mbit/s earlier
and 119.41 / 53.69 now. The stable reference also fell from 195.08 / 97.68
to 178.96 / 64.16 Mbit/s across those runners. Native/stable throughput ratios
remain about 0.668 raw and 0.84 WebSocket. These unpaired runs support a
latency improvement, not a universal throughput/CPU improvement claim.
Same-runner before/after loads and physical testing remain required before
production performance approval.

The actual four-call UDP ABI benchmark reduced Go allocation per 1,200-byte
exchange from approximately 4,293 to 443 bytes (IPv4) and 4,452 to 602 bytes
(IPv6), after warmup. This isolates stack/ABI work and does not include OS,
protocol encryption or WAN effects. The independent half-close regression
received only 550,704 of 1,048,576 bytes on d96679c and the full verified
1,048,576 bytes on the hardened core. No success/security criteria were relaxed.

A bounded borrowed-FD comparison completed 30 verified rows across stable
SOCKS, reviewed/current SOCKS and reviewed/current packet paths. Its synthetic
TCP client now retains bounded unacknowledged segments and performs retransmit/
zero-window probes instead of assuming lossless/window-free delivery. Synthetic
retransmissions and peer abrupt-close TLS errors remain recorded; they are not
interpreted as production OS throughput or hidden as node successes.
