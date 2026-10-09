# In-process packet stack compatibility gate

Experimental branch only: `feature/windows-native-tun-stage1`.
Stable comparison: version `0.4.11`, commit `90a1853114de3e4bcb3deed6747801c10bc5b370`.
This is a compatibility proof, not a full-device VPN release or final stack selection.

## Architecture under test

Raw IPv4/IPv6 packets -> gVisor TCP/UDP endpoints -> additive C ABI ->
`NetstackCoreBridge` -> existing C++ `Protocol`, `Transport`, `SecureStream`,
`XHttpStream`, `UdpTunnel` or `ShadowsocksUdp` -> the configured node.

The packet stack lives in the **existing** TLS/HTTP Go shared library, with one
Go runtime in the same process as the C++ engine. It is enabled only by
`scripts/Build.py --experimental-netstack`. Default builds exclude its Go code.
There is no alternate VPN engine, tun2socks child process, SOCKS handshake or
loopback SOCKS listener in the tested packet data path. The independent fixture
server is a local thread simulating the configured VLESS node.

All existing parser/protocol/transport source files, C ABI 2, JNI, .NET SDK and
old native experiments remain available. Existing vendor file contents are
preserved; only new netstack dependencies and vendor metadata are added.

## Reproducible dependency

- Module: `gvisor.dev/gvisor v0.0.0-20260122175437-89a5d21be8f0`.
- Source: `google/gvisor` commit `89a5d21be8f0440c78fa6bbc01f98e23021e7132`.
- Module checksum: `h1:Lk6hARj5UPY47dBep70OD/TIMwikJ5fGUGX0Rm3Xigk=`.
- Manifest checksum: `h1:QkHjoMIBaYtpVufgwv3keYAbln78mBoCuShZrPrer1Q=`.
- Go/desktop/Android toolchains remain pinned in `scripts/toolchains.json`.
- Source/license notices are shipped in the vendored dependency tree.

## ABI and lifetime

Packet ABI 1 is independent of the existing core/provider interfaces. Handles
are numeric; no Go pointer crosses into retained C++ state. C++ input buffers
are copied to Go-owned storage before endpoints can retain data. Output is
copied into caller-owned memory during the call. Calls for one packet stack,
including destruction, are serialized by one caller-owned worker.

TCP handshakes are asynchronous and bounded by the flow limit; UDP endpoints
preserve a complete source/destination tuple. TCP reads/writes preserve partial
progress and half-close; UDP preserves boundaries and empty datagrams. Buffer
undersizing is reported rather than silently truncating a UDP record. Stack
shutdown aborts pending handshakes and joins workers; completed TCP sessions
are released gracefully so queued data/FIN are not replaced by RST.

## Runtime evidence required

The dedicated workflow starts all three platform jobs without dependency order:

- Linux native build and execution.
- Windows native build and execution.
- Android ARM64 and x86_64 builds, plus execution of the x86_64 binary inside an
  Android API 35 emulator. This is Android runtime evidence, **not** phone/ARM64
  runtime evidence. ARM64 device acceptance remains a separate gate.

Each executed probe injects real, checksummed IP packets, performs the TCP
handshake, transfers deterministic payload through the actual C++ VLESS
transport over a real socket, and verifies bytes/address/port independently.
TCP tests include trailing data after client FIN. UDP tests include 0-, 1-,
512- and 1200-byte datagrams, including UDP port 443 without a special ban in
the new bridge. IPv4 and IPv6 are tested separately. Failure returns nonzero.

Resource tests log every warmup cycle, require four unchanged observations
within at most 24 cycles, then freeze the reference and run 32 cycles. These
cycles include a UDP endpoint and an incomplete TCP handshake. Any increased
FD/Windows handle count fails the probe; the test does not allow a rising floor.

## Measuring Go/C++ cost

Reports record successful ABI calls, bytes copied in each direction, Go heap
and cumulative allocations, goroutines and collections, and elapsed transfer
time. Separate 2,000-iteration measurements at 64, 512, 1500, 16384 and 65535
bytes compare a C++ two-copy control with a C++/Go copy roundtrip and include
before/after memory metrics. This is a **copy/ABI microbenchmark**, not proof
of complete VPN throughput or equivalence to the former app.

The first Linux trial exposed allocation of a new 64 KiB read buffer on empty
polls. The buffer is now owned/reused by the serialized stack. Retained
endpoint writes still copy input intentionally; no unsafe zero-copy lifetime
shortcut is used.

Final selection requires all platform runtime gates, support regression against
the stable core, and an equivalent-load end-to-end comparison. If the stack
cannot pass these gates or its complexity/resource cost is unacceptable,
implement the same fixture/bridge contract using lwIP and compare it before
selection. A build pass or small-copy microbenchmark alone does not select a
winner.

## Boundaries of this stage

- No Wintun/VpnService/Linux TUN device is activated by the new proof.
- No routes, DNS settings, firewall rules or full-device capture are changed.
- Per-flow connection/poll can wait for existing providers. Production
  scheduling needs asynchronous per-flow workers/bounded queues before a real
  device's packet-reader loop can use this bridge.
- Independent VLESS runtime fixtures prove interoperability at the bridge,
  not every public node's present reachability. Existing full protocol tests
  and original-node inventory comparisons remain required.
- Main is not updated. The stable app and old paths remain the rollback option.
