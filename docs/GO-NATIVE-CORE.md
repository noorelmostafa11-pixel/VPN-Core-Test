# vpn-core 0.5.14-go — Core guide

vpn-core is a publicly available, general-purpose Go networking core for
desktop and mobile VPN/proxy applications. This guide describes the current
source implementation on the selected branch: standalone execution, protocol clients and selected
servers, native TUN, routing, DNS, application integration and packaging.
The source version is defined in [VERSION](../VERSION); GitHub Releases are
published separately from source updates and workflow artifacts.

The latest additions include VLESS REALITY/Vision servers, SS2022/native UDP Shadowsocks servers, SS2022
inside ShadowTLS, VMess servers and VMess/VLESS MUX/XUDP server
framing, HTTPS/body-verified outbound health selection, SSH
forwarding servers, TUIC v5, ShadowTLS v2/v3 and Hysteria 1. Hysteria 2, AnyTLS and WireGuard
clients/servers are also included. Protocol-specific acceptance records and
remaining work are tracked in the
[capability register](FULL-SUPPORT-IMPLEMENTATION.md).

The implementation in `core/`, `cmd/` and `mobile/` is Go. It does not invoke a
C++ core, Xray/sing-box engine, external tun-to-socks process, or TLS helper DLL.
The existing project-owned Go TLS/QUIC, mKCP, VLESS encryption and legacy cipher
components are called directly. The C ABI is an optional thin compatibility
export built from Go; it is not required by the executable or Go SDK.

## Protocol clients and carriers

- VLESS: TCP/UDP, Vision, REALITY, MLKEM768+X25519 encryption, native/random
  records, zero/one RTT, identity relays, tickets and configured padding.
- VMess: AEAD and legacy alter-ID authentication, AES-GCM, ChaCha20-Poly1305,
  AES-CFB, none and zero.
- Trojan: TCP and UDP.
- Shadowsocks: the original 35 methods, including AEAD2017, SS2022, identity
  chains, XChaCha20, AES stream modes and historical stream ciphers.
- Raw TCP, HTTP header disguise, WebSocket/early data, HTTP Upgrade, gRPC/multi,
  legacy HTTP/2 including h2c, XHTTP modes/metadata/padding/download settings,
  HTTP/3, QUIC, mKCP packet headers/loss recovery, v2ray-plugin/mux and simple-obfs.
- TLS 1.2/1.3, supported uTLS fingerprints, ECH on supported paths, certificate
  names/pins/custom roots, legacy XTLS and FinalMask fragmentation.
- Hysteria 1/2, WireGuard, AnyTLS, TUIC v5 and ShadowTLS v2/v3 clients, with the
  TCP/UDP and authentication scope documented in their individual guides.
- SSH direct-tcpip forwarding with verified host identity; remote HTTP CONNECT,
  HTTPS CONNECT and SOCKS4/4a/5, including SOCKS5 authentication and UDP.

Original URIs/options and node IDs are retained. Configuration inspection does
not print credentials or encryption keys. `allowInsecure` remains informational;
certificate verification remains enforced.

## Protocol servers and local listeners

Servers are explicit entries in a routing profile's `inbounds` array, or are
started by the Go SDK through `Engine.StartServer`. Their routing, socket
protection, flow admission and shutdown use the same engine as client traffic.

| Server | Implemented scope and boundary |
| --- | --- |
| VLESS | Raw TCP with optional TLS or authenticated REALITY, UDP-over-TCP and MUX/XUDP; opt-in Vision uses TLS 1.3, padding/direct transitions and UDP-only MUX policy. REALITY target-handshake mirroring/PQ options, server encryption and additional carriers remain pending; [Vision guide](VLESS-SERVER.md), [REALITY scope](REALITY-SERVER.md) |
| VMess | Raw TCP/optional TLS, AEAD/opt-in legacy alter-ID, TCP/UDP/MUX, encrypted and masked/padded bodies; [guide](VMESS-SERVER.md) |
| Trojan | TLS TCP and UDP-over-TCP |
| Shadowsocks | All 35 methods over TCP/native UDP, SS2022 fixed identity chains, bounded replay/session handling and optional TCP TLS; [guide](SHADOWSOCKS-SERVER.md) |
| Hysteria 1 | Binary v3 TCP/UDP, xplus, negotiated Brutal and bounded lifetime; [guide](HYSTERIA1.md) |
| Hysteria 2 | Authenticated TCP/UDP and documented congestion/obfuscation options; [guide](HYSTERIA2.md) |
| WireGuard | Encrypted device and native server packet forwarding, including TCP/UDP IPv4/IPv6; [guide](WIREGUARD.md) |
| AnyTLS | Authenticated TLS streams, session reuse, padding and optional UOT v2 UDP; [guide](ANYTLS.md) |
| TUIC v5 | TLS-exporter authentication, TCP, native/QUIC UDP and fragmentation; [guide](TUIC.md) |
| ShadowTLS v2/v3 | Authenticated relay with embedded Shadowsocks or an explicit data backend; optional embedded UOT v2 UDP; [guide](SHADOWTLS.md) |
| SSH | Password/public-key direct-tcpip forwarding for one configured username per listener; reverse forwarding remains pending; [guide](SSH.md) |

Additional protocol options, general outbound mux, cross-parent XUDP migration,
GeoIP/geosite loaders, Redirect/TProxy, Naive, Tor, Snell and Tailcat
remain outside the current scope; consult the capability register before
configuring them.

The executable starts loopback SOCKS5 TCP/UDP by default. `--http-listen` and
`--mixed-listen` add loopback HTTP or combined HTTP/SOCKS listeners.
`--no-socks` disables the default SOCKS listener for HTTP/server-only setups.
Configured protocol servers use their explicit listen addresses and credentials.
They do not configure host routes or firewall policy.

## Routing, DNS and HTTPS health selection

Single-node `node.ini` files remain supported. `--config` also accepts a routing
JSON profile containing `outbounds`, optional `groups`/`rules`/`dns`/`inbounds`,
and a `final` outbound or group. For example:

```json
{
  "listen_port": 1080,
  "max_connections": 128,
  "outbounds": [
    {"tag": "node-a", "uri": "socks5://127.0.0.1:1081"},
    {"tag": "node-b", "uri": "socks5://127.0.0.1:1082"}
  ],
  "groups": [{
    "tag": "automatic",
    "mode": "url_test",
    "members": ["node-a", "node-b"],
    "url_test": {
      "urls": ["https://probe.example/status"],
      "expected_body": "vpn-probe-ok",
      "interval_seconds": 30,
      "timeout_ms": 3000
    }
  }],
  "final": "automatic"
}
```

The example proxies and HTTPS endpoint are placeholders. Supply reachable
outbounds and a real endpoint with the expected body before running
`vpn-core --config routing.json`.

Rules match domains, suffixes, regexes, destination/source CIDRs, ports/ranges
and TCP/UDP. Process/interface matching uses metadata supplied by the host SDK;
automatic OS discovery remains pending. Direct, proxy and block choices share
the flow budget. Groups support manual selection, round-robin, bounded
connection-establishment failover and `url_test` selection. Routing updates are
validated before an atomic replacement; established connections keep their
selected path. Runtime listener/budget changes require separate lifecycle
handling. Delivered application data is not replayed during failover.

HTTPS health selection requires verified endpoint TLS, HTTP status 200 and a
nonempty bounded response body; `expected_body` adds a content check. The
fastest currently verified member is selected. If none is healthy, dialing
returns `NO_HEALTHY_OUTBOUND`. At most 16 probes run per engine round, with
four concurrently and a minimum five-second pause. Catalogs are scanned
gradually; optional health workers are created only when configured.
TCP/QUIC setup alone does not prove Internet access, and HTTPS health does not
establish UDP reachability. See [URL-TESTING.md](URL-TESTING.md).

Optional DNS policy adds HTTPS resolver groups, domain rules, failover and
bounded stable IPv4/IPv6 FakeIP mappings. It retains the tunnel DNS path and
separate cache identities during policy changes. External rule-set import and
broader protocol sniffing remain pending.

An opt-in bearer-authenticated loopback management API exposes `GET /stats`,
`GET /routing`, `PUT /routing`, `POST /select`, `PUT /dns`,
`GET /health` and `POST /health/check`. Start it with `--api-listen` plus
`--api-token-file`, or `Engine.StartManagementAPI`; the token must be
32–256 characters. Health/routing responses omit node URIs and credentials.
Existing single-node profiles create no routing or health controller.

## Native TUN and host responsibilities

`Engine.StartTUN(PacketDevice, mtu)` accepts raw IPv4/IPv6 packets. The embedded
gVisor stack handles TCP reliability and UDP. Both use the same project protocol
dialers as SOCKS, directly. Queues and concurrent flows are bounded.

`OpenTUN` creates Linux `/dev/net/tun`, Windows Wintun, macOS utun and BSD TUN
devices through the MIT WireGuard TUN library. The separate WireGuard protocol
implementation is described in [WIREGUARD.md](WIREGUARD.md). Windows needs
administrator rights and the official architecture-matched, signed
`wintun.dll` beside the executable. Linux needs CAP_NET_ADMIN.

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
`Stats` and `Close`. `core.NewRouterEngine` creates an engine from a routing
profile. Optional controls include `Router().Select`, `Router().Reload`,
`ConfigureDNS`, `URLHealth`, `RequestURLTest`, `StartServer`, `StartHTTP`,
`StartMixed` and `StartManagementAPI`. Each engine has its own cancellation
and hooks. Availability through the mobile/C bindings is documented separately;
a Go SDK method is not automatically a new C ABI or gomobile export.

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
authentication rejection, TCP/UDP and carrier behavior. Official Xray,
Hysteria, AnyTLS and sing-box executables are test-only references, with explicit
versions and opt-in reference paths in their protocol guides. Optional skipped
reference tests do not establish interoperability. Public-node connectivity,
physical-device VPN integration and Windows route/DNS acceptance have separate
coverage; local tests and cross-builds do not substitute for them.
Historical C++ reports describe earlier main revisions and are not results for
the current Go implementation.

## Packages and GitHub Releases

The [Build & Test workflow](../.github/workflows/core-validation.yml) runs on
pushes to `main`/`feature/go-native-core` and by manual dispatch. Desktop
runtime jobs test and package Windows/Linux/macOS; portable jobs cross-build
amd64/arm64 executables for Windows, Linux, macOS, FreeBSD and OpenBSD plus
Android ARM64, and the mobile job builds the Android ARM64 AAR.

Package a local build with:

```text
python scripts/Package-Go.py --build build/windows-amd64
```

The package name is derived from `VERSION` and the build provenance, for example
`dist/vpn-core-0.5.12-go-windows-amd64.zip`. It contains only manifest-listed
runtime files, build provenance/hashes, the core guide and component license
snapshots. Desktop workflow artifacts contain these packaged ZIPs; the outer
artifact download ZIP is a separate wrapper. The Android artifact contains
`vpn-core.aar`.

Workflow artifacts are retained for three days. The current workflow does not
create tags, upload release assets or publish Releases. To publish the current
version:

1. Use packages from a successfully validated build of the intended main
   revision, with matching source provenance.
2. Open [Draft a new release](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/releases/new),
   create a new tag such as `v0.5.12-go` and select the intended `main` revision.
3. Add an English title and release notes, then attach the inner packaged ZIPs
   and/or Android AAR. Include package SHA-256 sidecars if you generate them;
   the packager itself writes hashes inside the ZIP rather than an outer
   ZIP `.sha256` file.
4. Select **Set as latest release** and publish. This updates the repository's
   latest release independently of the VERSION file and Actions artifacts.

GitHub's automatically attached source archives contain source code rather
than compiled runtime packages.

The separate [Node Acceptance workflow](../.github/workflows/node-acceptance.yml)
is dispatched manually on main and tests the pinned 72,767 original node URIs
in 15 shards. Its reports document live-node observations independently of the
local wire suite.

## Authorship and ownership

Copyright (c) 2026 **noorelmostafa11-pixel**, the original project owner.
This is a public project with ownership and distribution terms preserved in
[NOTICE.md](../NOTICE.md) and [OWNERSHIP.md](../OWNERSHIP.md).
Upstream components remain the work of their respective authors and retain
their licenses; see [COMPONENTS.md](COMPONENTS.md). Binary distributions preserve
their license snapshots and notices.
