# Go core 0.5.8

Optional routing, DNS policy, remote HTTP/SOCKS, local HTTP/mixed and initial
server support are described in [the full implementation record](FULL-SUPPORT-IMPLEMENTATION.md).
This is an incremental extension; the remaining protocol/server gaps are explicit.
TUIC v5, ShadowTLS v2/v3, Hysteria 2, AnyTLS, WireGuard and SSH extensions
have individual implementation and acceptance records linked from that table.

The implementation in `core/`, `cmd/` and `mobile/` is Go. It does not invoke a
C++ core, Xray/sing-box engine, external tun-to-socks process, or TLS helper DLL.
The existing project-owned Go TLS/QUIC, mKCP, VLESS encryption and legacy cipher
components are called directly. The C ABI is an optional thin compatibility
export built from Go; it is not required by the executable or Go SDK.

## Protocol and carrier parity

- VLESS: TCP/UDP, Vision, REALITY, MLKEM768+X25519 encryption, native/random
  records, zero/one RTT, identity relays, tickets and configured padding.
- VMess: AEAD and legacy alter-ID authentication, AES-GCM, ChaCha20-Poly1305,
  AES-CFB, none and zero.
- Trojan: TCP and UDP.
- Shadowsocks: all 35 methods from main, including AEAD2017, SS2022, identity
  chains, XChaCha20, AES stream modes and historical stream ciphers.
- Raw TCP, HTTP header disguise, WebSocket/early data, HTTP Upgrade, gRPC/multi,
  legacy HTTP/2 including h2c, XHTTP modes/metadata/padding/download settings,
  HTTP/3, QUIC, mKCP packet headers/loss recovery, v2ray-plugin/mux and simple-obfs.
- TLS 1.2/1.3, existing uTLS fingerprints, ECH, certificate names/pins/custom
  roots, legacy XTLS and FinalMask fragmentation.

Original URIs/options and node IDs are retained. Configuration inspection does
not print credentials or encryption keys. `allowInsecure` remains informational;
certificate verification is enforced as in main.

## Native TUN and host responsibilities

`Engine.StartTUN(PacketDevice, mtu)` accepts raw IPv4/IPv6 packets. The embedded
gVisor stack handles TCP reliability and UDP. Both use the same project protocol
dialers as SOCKS, directly. Queues and concurrent flows are bounded.

`OpenTUN` creates Linux `/dev/net/tun`, Windows Wintun, macOS utun and BSD TUN
devices through the MIT WireGuard **device** library. This adds no WireGuard VPN
protocol. Windows needs administrator rights and the official architecture-
matched, signed `wintun.dll` beside the executable. Linux needs CAP_NET_ADMIN.

The core intercepts native TCP/UDP DNS and sends wire-format DNS over HTTPS
through the configured node. `--dns-listen 127.0.0.1:53` also provides local
TCP/UDP DNS for Windows. The default DNS policy prefers IPv4 records while
retaining IPv6-only names. A bounded cache remembers unique names for IP
destinations. No external UDP DNS or proxy engine is required.

HTTP Host/TLS SNI destination override is shared by SOCKS and Native TUN for
public web ports 80, 443, 8080 and 8443. The initial read is bounded to 16 KiB and
150 ms; consumed bytes are replayed unchanged. ECH cover names are not used as
destinations. Opaque web flows retain their IP unless a unique unexpired DNS
mapping is available. Private destinations and non-web ports retain their
existing handshake behavior. SOCKS acceptance can precede destination
negotiation for sniffed flows; only successful upstream negotiation emits the
`negotiated` event. Verify HTTPS/body, not SOCKS acceptance alone.

Bootstrap TCP dialing prefers IPv4 and starts the other family after 250 ms
(or immediately on failure), with at most two concurrent attempts. Losing
attempts are joined and their sockets closed. CLI bootstrap addresses are
pinned before TUN startup; the original node URI remains intact.

The host still owns OS addresses, routes and DNS registration. The executable
does not silently change the host network. The Windows package includes
`Run-Native-Tunnel.ps1`: it configures both families, registers the core's local
DNS temporarily and restores owned settings on stop, with a crash watcher.
`--bind-interface` protects Windows upstream sockets from recapture.
Windows hosts can select `-ProxyPort` and `-TunMTU`. With `-Exchange`,
`-SessionTimeout 0` keeps an application session active until it signals stop.
`-OwnerPid` plus `-OwnerTicks` lets both the coordinator and independent watcher
restore the network after the external application's process exits. Defaults
retain standalone behavior; no application binary or application source is
required in the core repository.
Protect every upstream socket and resolve bootstrap names through the physical
network with `Hooks`. A protection/resolver failure never falls back to a direct
connection. Close the engine and wait for it before releasing callback resources.
When a protector is supplied without a custom resolver, fallback Go bootstrap
DNS sockets also pass that protector before sending bytes. The C ABI keeps both
resolver and protector callback leases until their calls return, including DNS
work that outlives a canceled lookup. It gates new callbacks before draining.
Do not call `Close` synchronously from a callback that Close needs to join.

Examples:

```text
vpn-core --config node.ini
vpn-core --config node.ini --tun vpn0 --tun-only --tun-mtu 1500
vpn-core --config node.ini --tun-fd 5 --tun-only
powershell -NoProfile -ExecutionPolicy Bypass -File Run-Native-Tunnel.ps1 -Config node.ini
```

The first starts loopback SOCKS5 TCP/UDP. The other commands start packet
forwarding; the host still sets the corresponding OS addresses/routes. A supplied
descriptor is duplicated; closing the core does not close the app's original fd.

Optional node.ini settings: `sniffing=true`, `native_dns=true`,
`prefer_ipv4=true`, `prefer_tcp=false`. The Windows launcher selects TCP mode:
native UDP/443 is rejected immediately so browsers retry TCP, and DNS HTTPS/SVCB
binding records return empty answers. Other UDP remains supported. Normal SDK
defaults retain UDP/443. Set `prefer_ipv4=false` for dual-family DNS answers.
Sniffing and DNS interception can be disabled independently.

## Browser concurrency and diagnostics

The default connection budget is 128; `max_connections` accepts 1 through 512.
Explicit existing settings, including 32/64, keep their values. The budget is
shared by SOCKS control connections and native TCP/UDP flows. An exhausted budget
rejects immediately with a `CONNECTION_LIMIT` event in phase `ADMISSION_FAILED`.
No unbounded queue is created; closing a flow releases its slot.

Relay idle retirement uses one timer per connection and activity in either
direction. It no longer resets OS deadlines four times per payload chunk.
Normal idle retirement is a `closed` event with `IDLE_TIMEOUT`, rather than a
protocol failure. Close events include duration and transferred byte counts;
all events include protocol, carrier, active count and limit, without destination
names, server addresses, URIs, credentials or keys. Transport/authentication
failures remain failures. These changes alone do not establish the cause of
every timeout in earlier browser reports; repeat that workload on the new build.

## Embedding and mobile

Go hosts use `core.ParseURI`, `core.NewEngine`, `StartSOCKS`, `StartTUN`, `Events`,
`Stats` and `Close`. Each engine has its own cancellation and hooks.

The optional C shared library retains ABI 2 exports, run/stop/state/listen-port,
bounded diagnostic events, callback counting and single-run behavior. Its header
is generated alongside the library. Additive `vpn_core_run_tun_fd_config` and
`vpn_core_run_native_tun_config` exports start native TUN forwarding.

Stop revokes the listener synchronously before publishing a zero port. Shutdown
closes independent resources concurrently and joins all of them. Concurrent
`Close` callers wait for the same complete shutdown, including packet pumps.

`mobile/` is gomobile compatible:

- Android: `StartFD` consumes a duplicated fd established by VpnService, and
  requires a socket protector. Supply a Resolver backed by the underlying
  Android Network. The host owns the VpnService and permission prompt.
- Android/iOS: `StartPackets` + `Session.InjectPacket` accept packets from the
  OS VPN service; `PacketReceiver.ReceivePacket` sends responses to it. On iOS,
  connect this to NEPacketTunnelFlow in an entitled Network Extension.
- `Session.Close` releases the engine; byte counters are available.

The Android AAR is generated by gomobile from the Go implementation. The mobile
builder stages exact patched TLS/QUIC modules so gomobile's temporary module
cannot silently switch to unpatched upstream code. Android supports 16 KB pages.
Apple binding builds require macOS/Xcode and the host's VPN entitlement.

## Reproducible build

Go 1.27 or newer is required. The default is a stripped, portable executable:

```text
python scripts/Build-Go.py --target windows --arch amd64 --wintun
python scripts/Build-Go.py --target linux --arch arm64
python scripts/Build-Go.py --target darwin --arch arm64
python scripts/Build-Go.py --target android --abi arm64-v8a
python scripts/Build-Go.py --shared
python scripts/Build-Mobile.py --target android/arm64 --output dist/vpn-core.aar
```

`--shared` needs a target C compiler for the Go C ABI export. Android shared/mobile
builds need SDK/NDK/JDK. A combined Android AAR is explicit:
`--target android/arm,android/arm64,android/386,android/amd64`.

Versions/checksums are pinned in go.mod/go.sum, vendor and
`components/patches/manifest.json`. After `go mod vendor`, run
`python scripts/Apply-Go-Component-Patches.py`. The patch script refuses changed
upstream bytes. Dependency licenses and original project ownership are retained.

Validation:

```text
python -m pip install -r tests/requirements-go.txt
go test -race ./core ./mobile
python scripts/Validate-Go.py
```

The test suite uses independent Python/Go peers and validates actual payloads,
authentication rejection, TCP/UDP and carrier behavior. Historical C++ reports
under docs describe main; they are not results for this Go implementation.
