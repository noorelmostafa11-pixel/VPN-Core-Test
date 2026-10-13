# Support comparison — 13 October 2026

Scope: original `main` at `63cc65b3524d3ee3f38dcd048c69af4802047a06` and
Go Native 0.5.2 at `1bfd433f94c31d38ed66a48cd7cd6f0c1a6edc73`.
This distinguishes configured support, independent wire tests and live
Internet acceptance. A protocol family being present does not imply complete
compatibility with every upstream feature or every public node.

## Migration from main

The reviewed implementations retain the same four outbound VPN families:
VLESS, VMess, Trojan and Shadowsocks. Current Go validation accepts only these
families; importing WireGuard's device library provides TUN devices, not the
WireGuard VPN protocol.

| Capability in main | Go Native status | Evidence/limit |
| --- | --- | --- |
| VLESS TCP/UDP, Vision, REALITY, VLESS encryption | Retained | Independent wire/authentication tests; live coverage is narrower |
| VMess AEAD and alter-ID legacy authentication/ciphers | Retained | Protocol/crypto tests; not a public-node Internet sweep |
| Trojan TCP/UDP | Retained | Independent framing/UDP tests |
| Shadowsocks 35 configured methods, AEAD2017/SS2022 and identity chains | Retained | Cipher/framing tests including legacy methods |
| TCP/HTTP headers, WS/early data, HTTP Upgrade, gRPC/multi | Retained | Transport tests and validation |
| XHTTP modes, metadata/padding, alternate download and HTTP/3 | Retained | Pinned transport settings plus wire tests |
| Legacy HTTP/2/h2c, QUIC and mKCP | Retained | Independent carriers; QUIC transport is not Hysteria/TUIC |
| TLS/uTLS, ECH, custom roots/pins, legacy XTLS, FinalMask | Retained in implemented scope | Unsupported options are rejected; not full upstream parity |
| SOCKS TCP/UDP and C ABI/mobile hooks | Retained | Lifecycle/callback/UDP tests |
| TUN packet forwarding | Replaced by embedded gVisor stack | IPv4/IPv6 packet tests; host still owns OS policy |
| DNS/HTTP-TLS destination handling | Added/shared in Go | Native DNS-over-HTTPS and bounded name recovery |

No removed family was identified in the source review. A saved local comparison
from 11 October processed 78,334 original URI rows: main and Go both accepted
77,346, with `lost_support=0` and `semantic_changes=0`. A smaller saved comparison
processed 5,075 rows, both accepting 5,073 with the same zero-regression result.
These are prior configuration comparisons, not a new run against today's
binaries or proof that those nodes are online. The report lacked source/binary
hashes; it is supporting historical evidence rather than a fully pinned fresh
acceptance result. A fresh rerun on 13 October was stopped by Windows error
225 and quarantine, documented in [the incident report](WINDOWS-QUARANTINE-2026-10-13.md).

Earlier local independent protocol/carrier validation passed 161 tests and
skipped two optional external-server cases. Native Windows Internet acceptance
used two available VLESS REALITY nodes and three HTTPS sites each. User
confirmation of a separate GUI connection does not expand that protocol scope.

## Features available upstream but absent here

This core is a single-node client engine with SOCKS/TUN entry points. It is not
a complete replacement for all Xray or sing-box configuration/server features.
The following gaps existed outside main's four-family scope; they are not
protocol families lost specifically during the Go migration.

| Missing capability | Reference implementation |
| --- | --- |
| WireGuard VPN protocol and Hysteria 2 | Xray and sing-box |
| Remote HTTP/SOCKS proxy outbounds | Xray and sing-box; our SOCKS support is a local inbound |
| TUIC, Hysteria 1, AnyTLS, ShadowTLS, Naive, SSH and Tor outbounds | sing-box |
| Snell/Tailcat and additional endpoint/service modes shown in current docs | sing-box; version/build availability must be checked |
| VLESS/VMess/Trojan/Shadowsocks server inbounds, HTTP/mixed listeners, redirect/TProxy | Broader Xray/sing-box inbound configurations |
| General multiple-outbound routing, GeoIP/geosite/rule sets, selectors/balancers and automatic URL testing | Upstream routing/policy layers |
| Upstream-wide multiplexing/XUDP/UoT, reverse proxy/fallback and management APIs | Not supplied by this core's narrower components |
| Configurable multi-policy DNS/FakeIP, ACME and endpoint/service integrations | Broader sing-box/Xray configuration features |

The existing v2ray-plugin mux implementation is narrower than a general
upstream multiplexing engine. DNS caching/name recovery is narrower than
FakeIP or a full rule-driven DNS engine. Some functionality can be supplied by
the host application, but that does not make it implemented in this core.

Sources reviewed on 13 October: [Xray outbound list](https://xtls.github.io/en/config/outbounds/),
[Xray Hysteria version 2](https://xtls.github.io/en/config/outbounds/hysteria.html),
[sing-box outbound list](https://sing-box.sagernet.org/configuration/outbound/),
[sing-box Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/),
[AnyTLS](https://sing-box.sagernet.org/configuration/outbound/anytls/) and
[SSH](https://sing-box.sagernet.org/configuration/outbound/ssh/).
These are current documentation snapshots, not a claim about every older
installed build. No application binaries, recovered application source,
private node URIs, DPAPI data or recordings are included in this repository.
