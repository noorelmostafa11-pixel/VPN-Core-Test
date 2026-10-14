# vpn-core 0.5.13-go

A public, general-purpose Go networking core for VPN and proxy applications,
available to desktop and mobile users and developers. It provides a standalone
executable, native TUN packet forwarding, protocol clients and selected servers,
and APIs for application integration.

The current `main` branch contains the Go implementation. The source version is
defined in [VERSION](VERSION); published downloads are listed separately under
[Releases](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/releases).
The executable and SDK use the same engine and protocol implementations.

## What's new in this source revision

- **VLESS Vision servers:** native TLS 1.3, authenticated flow policy, padded
  TCP and guarded direct transitions, UDP-over-TCP and UDP-only MUX/XUDP;
  [implementation/acceptance](docs/VLESS-SERVER.md).
- **Shadowsocks servers:** all 35 existing cipher methods now support native
  UDP; SS2022 adds TCP, identity chains, replay protection and bounded sessions;
  [implementation/acceptance](docs/SHADOWSOCKS-SERVER.md).
- **SS2022 inside ShadowTLS:** embedded TCP and UOT v2 for all three modern
  ciphers, including independent client/server payload tests.
- **VMess servers:** AEAD and opt-in legacy authentication, TCP/UDP, verified
  TLS, chunk masking/padding and authenticated lengths;
  [implementation/acceptance](docs/VMESS-SERVER.md).
- **VMess/VLESS MUX servers:** concurrent TCP sessions and XUDP destination
  framing with bounded queues, shared flow limits and protected routing;
  [scope](docs/MUX-SERVER.md).
- **ShadowTLS v2 connection handling:** authenticated TLS residual records are
  included before switching to proxy data; [timing and limits](docs/SHADOWTLS.md).
- **Hysteria 1 clients and servers:** v3 TCP/UDP, xplus, verified TLS and
  bounded connection reuse; [implementation/acceptance](docs/HYSTERIA1.md).
- **HTTPS health selection:** optional `url_test` groups verify the HTTPS
  certificate, status and response body, then select the fastest verified
  outbound. Large catalogs are scanned gradually with bounded concurrency.
- **SSH forwarding servers:** password or authorized public-key authentication,
  explicit server host keys, shared channel limits and protected routing.
- **TUIC v5 clients and servers:** authenticated TCP, native/QUIC UDP relay,
  fragmentation and bounded connection reuse.
- **ShadowTLS v2/v3 clients and servers:** Shadowsocks payloads, strict v3
  integrity checks and optional UOT v2 UDP inside the authenticated TCP stream.
- **AnyTLS, WireGuard and Hysteria 2:** client/server implementations with
  protocol-specific TCP/UDP support and lifecycle limits.
- **Optional routing and DNS policies:** multiple outbounds, selection,
  connection-establishment failover, domain/IP/port rules, DNS policies,
  bounded FakeIP mappings and authenticated local management.

Implementation boundaries and validation records are maintained in the
[capability register](docs/FULL-SUPPORT-IMPLEMENTATION.md).

## Capabilities

| Area | Current scope |
| --- | --- |
| Protocol clients | VLESS, VMess, Trojan, Shadowsocks, Hysteria 1/2, WireGuard, AnyTLS, TUIC v5, ShadowTLS v2/v3, SSH, HTTP/HTTPS and SOCKS4/4a/5 proxies |
| Transports | TCP, WebSocket/early data, HTTP Upgrade, gRPC, HTTP/2/h2c, XHTTP, HTTP/3, QUIC, mKCP, HTTP disguise, simple-obfs and v2ray-plugin |
| Security | TLS 1.2/1.3, supported uTLS fingerprints, ECH on supported paths, REALITY, Vision, VLESS encryption, certificate names/pins/custom roots and FinalMask fragmentation |
| Local interfaces | SOCKS5 TCP/UDP, HTTP and mixed HTTP/SOCKS listeners, native TUN for IPv4/IPv6 TCP/UDP |
| Integration | Go SDK, optional C ABI 2 shared library, Android AAR and Android/iOS packet interfaces |
| Control | Routing/DNS updates, selectors, HTTPS health checks, statistics and redacted diagnostic events |

Options and server support vary by protocol; the table is not a claim of full
Xray/sing-box feature parity. General outbound multiplexing,
GeoIP/geosite loaders, Redirect/TProxy and several additional protocols remain
pending. See the [core guide](docs/GO-NATIVE-CORE.md) for the implemented scope.

## Build and run

Go 1.27 or newer is required; GitHub CI pins Go 1.27.1 and Python 3.12.

```text
python scripts/Build-Go.py --target windows --arch amd64 --wintun
build/windows-amd64/vpn-core.exe --config node.ini
```

The existing single-node configuration format is supported:

```ini
node_uri=vless://12345678-1234-4567-9234-567812345678@example.test:443?security=tls&type=tcp
listen_port=1080
connect_timeout_ms=10000
idle_timeout_ms=60000
max_connections=128
```

Replace the example URI with your own server configuration. The listener starts
on loopback. Routing JSON profiles use the same `--config` option; examples are
in the [core guide](docs/GO-NATIVE-CORE.md#routing-dns-and-https-health-selection).

Certificate verification remains enforced, including when imported profiles
contain legacy insecure flags. The default shared connection budget is 128;
`max_connections` accepts 1–512. Admission failures and idle closure report
`CONNECTION_LIMIT` and `IDLE_TIMEOUT` respectively.

## Native TUN and application integration

```text
vpn-core --config node.ini --tun vpn0 --tun-only
```

The engine handles IPv4/IPv6 TCP/UDP packets through its embedded gVisor stack.
The host application or launcher configures OS addresses, routes, DNS and
upstream socket protection. Windows requires administrator rights and the
official Wintun DLL. The Windows package includes a launcher and restoration
watcher; see [Windows tunnel setup](docs/WINDOWS-TUNNEL.md).

Android applications use VpnService with `mobile.StartFD` or the packet API.
iOS applications connect the packet API to an entitled Network Extension.
Application permissions, OS VPN services and host network policy are supplied
by the integrating application.

## Platforms and packages

```text
python scripts/Build-Go.py --target linux --arch arm64
python scripts/Build-Go.py --target darwin --arch arm64
python scripts/Build-Go.py --target windows --arch amd64 --shared --wintun
python scripts/Build-Mobile.py --target android/arm64 --output dist/vpn-core.aar
```

The default build produces a standalone executable. `--shared` additionally
builds the optional C ABI library and requires a target C compiler. Portable CI
cross-builds Windows, Linux, macOS, FreeBSD and OpenBSD on amd64/arm64, plus
Android ARM64. Runtime CI runs on Windows, Linux and macOS; a successful
cross-build does not establish runtime or VPN integration on every target.
Apple bindings require macOS/Xcode and the host application's VPN entitlement.

## Validation and GitHub Actions

```text
python -m pip install -r tests/requirements-go.txt
go test -race ./core ./mobile
python scripts/Validate-Go.py
```

[Build & Test](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/workflows/core-validation.yml)
runs on pushes to `main` and `feature/go-native-core`, and supports manual
dispatch. It builds desktop packages, portable executables and the Android AAR.
Independent reference tests need the reference binaries documented for each
protocol; skipped optional tests do not count as interoperability passes.

[Node Acceptance - 15 Shards](https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/workflows/node-acceptance.yml)
is a separate, manually dispatched workflow on `main`. It tests the pinned
72,767 original node URIs through a source-built Go core and produces reports.
Public-node results are separate from local protocol tests.

Build & Test uploads packages as workflow artifacts, retained for three days.
It does not automatically publish a GitHub Release. To publish a version, create
a release with a new tag on `main`, attach the packaged binaries from a matching
build, and select **Set as latest release**. See the
[release packaging instructions](docs/GO-NATIVE-CORE.md#packages-and-github-releases).

## Documentation

- [Core, TUN, SDK and build guide](docs/GO-NATIVE-CORE.md)
- [Capability register and remaining work](docs/FULL-SUPPORT-IMPLEMENTATION.md)
- [HTTPS health selection](docs/URL-TESTING.md)
- Protocol guides: [Hysteria 1](docs/HYSTERIA1.md), [Hysteria 2](docs/HYSTERIA2.md),
  [WireGuard](docs/WIREGUARD.md), [AnyTLS](docs/ANYTLS.md),
  [TUIC v5](docs/TUIC.md), [ShadowTLS](docs/SHADOWTLS.md) and [SSH](docs/SSH.md)
- [Components and upstream provenance](docs/COMPONENTS.md)

## Authorship and ownership

Copyright (c) 2026 **noorelmostafa11-pixel**, the original project owner.
Original project ownership and distribution terms are preserved in
[NOTICE.md](NOTICE.md) and [OWNERSHIP.md](OWNERSHIP.md).
Third-party components retain their respective authorship and licenses;
binary packages include their notices and license snapshots.
