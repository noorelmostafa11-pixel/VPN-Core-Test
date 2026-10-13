# Full capability implementation record

The owner requested the complete scope of the 14-page engineering report on
13 October 2026, **including protocol servers**. The report's recommendation to
defer servers does not narrow that request. This is an implementation record,
not a declaration that full Xray/sing-box parity has been achieved.

Input PDF SHA256:
`cba4fda7bcf857b5ed03944457b7050aa43b81c28efabe39d2d133f8fcc4fa09`.
Starting Go branch: `5e340974a50b23ab69b7a3b2d1ea3afcf5be5756`.
The engine baseline is `1bfd433f94c31d38ed66a48cd7cd6f0c1a6edc73`.
Preserved main: `63cc65b3524d3ee3f38dcd048c69af4802047a06`.
Application binaries/source, private profiles and the PDF are not repository
deliverables. The implementation remains Go and does not launch another proxy
engine. Optional features must not create workers/listeners when unused.

## Complete gap register

"Baseline" means the existing implemented scope; it does not imply all upstream
options or public nodes were tested. "Added" means implementation plus local
payload tests; Internet/other-engine acceptance remains separate. "Partial"
states its boundary. "Pending" must not be advertised as supported.

| Report capability | Current implementation / remaining work |
| --- | --- |
| VLESS, VMess, Trojan, Shadowsocks clients | Baseline; retain independent wire tests |
| SS2022, VLESS REALITY/Vision/encryption, VMess legacy/alter-ID | Baseline client scope; retain authentication and cipher tests |
| ShadowTLS v2 and v3; Shadowsocks with ShadowTLS | Pending client/server and independent-reference tests |
| Hysteria 1 and 2 | Pending authentication, TCP/UDP, congestion control, obfuscation and reconnect tests |
| TUIC | Pending client/server, authentication and both UDP relay modes |
| AnyTLS | Pending client/server, session reuse, padding updates and UDP-over-TCP |
| WireGuard VPN | Pending protocol endpoint; current TUN device dependency is not protocol support |
| Remote HTTP/HTTPS proxy | Added HTTP CONNECT and verified TLS path; preserve response read-ahead |
| Remote SOCKS4/4a/5 | Added, including SOCKS5 credentials and UDP association; SOCKS4 is IPv4 TCP by specification |
| SSH, Naive, Tor | Pending client implementations and reference/version/platform constraints |
| Snell, Tailcat | Pending: establish exact reference version and protocol scope before implementation |
| Raw TCP, UDP, WS/early data, HTTP Upgrade, gRPC/multi, HTTP2/h2c | Baseline carriers; retain regression tests |
| XHTTP modes, metadata, padding and download settings | Baseline implemented scope; preserve original URI semantics |
| HTTP3, QUIC, mKCP, HTTP disguise, simple-obfs, v2ray-plugin | Baseline carriers, distinct from Hysteria/TUIC protocols |
| TLS1.2/1.3, uTLS, ECH, REALITY, legacy XTLS, FinalMask | Baseline implemented scope; certificate verification remains enforced |
| General multiplexing and XUDP/UoT | Pending; current plugin mux does not satisfy general mux |
| Multiple configured outbounds | Added optional routing engine, shared flow budget |
| Domain/suffix/regex and destination IP/CIDR rules | Added; original destination IP retained after sniffing |
| GeoIP/geosite and named rule sets | Pending loaders, indexing, limits and update integrity |
| Port/range and TCP/UDP rules | Added shared by SOCKS, TUN and DNS upstream dialing |
| Process and interface rules | Partial: SDK-supplied metadata; native OS process/interface discovery still pending |
| Direct/proxy/block and split tunneling | Added routing decisions; Windows host policy and direct-name bootstrap integration still require acceptance |
| Selector, balancer and failover | Added selector, round-robin and bounded connection-establishment failover; reuse the last successful alternative, at most 16 attempts including nested groups; no replay of delivered application data |
| URL testing / healthy-node selection | Pending HTTPS/body probes, bounded scheduling and health state |
| Multi-hop / outbound detour | Partial: tested TCP proxy chain; UDP chain/carrier compatibility pending |
| Dynamic routing | Added validated atomic replacement; existing connections retain their selected path |
| DNS inside tunnel, DoH, local TCP/UDP DNS, IPv4 preference / IPv6 | Baseline retained, with shared routing for upstream connections |
| DNS cache and name recovery | Baseline bounded cache; policy updates use separate cache identities |
| DNS domain rules and multiple policy upstreams | Added HTTPS resolver groups with failover and domain rules |
| FakeIP | Added bounded stable IPv4/IPv6 mappings; no recycling during engine lifetime |
| DNS hijack / advanced protocol sniffing | Partial baseline; additional interception/sniff protocols pending |
| Domain / advertisement blocking | Added explicit domain/suffix block rules; external rule-set import pending |
| Strict kill switch | Pending optional host policy; must not replace automatic network restoration |
| Network restoration / automatic recovery | Existing Windows launcher/watchers; expanded policy/network-loss acceptance pending |
| SOCKS5 TCP/UDP inbound and native TUN | Baseline; retain packet/flow/lifecycle regression tests |
| HTTP and mixed HTTP/SOCKS inbound | Added loopback listeners, CONNECT and HTTP body forwarding |
| Redirect and TProxy | Pending platform-specific listeners and original-destination handling |
| VLESS, Trojan, Shadowsocks server inbounds | Partial: raw TCP with optional TLS (required for Trojan); VLESS/Trojan UDP-over-TCP, Shadowsocks legacy/AEAD2017 TCP. Payload tests with an independent Xray 26.7.28 client passed for VLESS, Trojan, SS AES-256-GCM and ChaCha20-Poly1305. Vision/REALITY/encryption, server carriers, SS2022/native UDP and remaining options are pending |
| VMess server inbound | Pending, including AEAD/legacy authentication and packet framing |
| Other protocol server inbounds | Pending with their corresponding client protocols |
| Reverse proxy / server fallback | Pending authenticated reverse channels and fallback semantics |
| General management API | Added opt-in authenticated loopback stats, selection, route and DNS updates; wider API/events scope pending |
| Statistics / connections / events | Baseline plus SDK flow accounting; richer per-outbound connection inventory pending |
| Go SDK / C ABI / Android AAR / iOS packet hooks / Windows Wintun | Baseline interfaces retained; bind optional routing and new protocol controls across interfaces |
| Windows VPN service | Pending opt-in service host, lifecycle/recovery/install/remove acceptance |

## Acceptance requirements

For every added protocol: malformed settings, authentication rejection,
handshake and real bidirectional payloads, TCP/UDP where the protocol supports
them, an independent reference implementation, repeated connect/disconnect,
owner loss, protection failure and supported-target builds. Record source and
reference versions. Configuration acceptance is not network acceptance.

For routing/DNS: policy replacement must be atomic, protection errors must not
fall back to direct traffic, block decisions must not trigger alternate exits,
all flow budgets/queues/caches must remain bounded, and Close must join owned
workers. Packet tests do not establish Windows route/DNS recovery or Internet
access. Live acceptance must verify HTTPS response bodies and restore host
network state. Features with platform-specific requirements retain explicit
platform limits instead of a false "all environments" claim.

The former quarantine incident and Microsoft submission concern the exact
0.5.2 executable hash. They are not a safety determination for later binaries.

## 0.5.3 configuration and verification boundary

`--config` accepts the existing node.ini and an optional routing JSON profile.
The following synthetic profile demonstrates explicit direct and block paths;
production VPN profiles replace/add node URIs and select a proxy as final.
Routing profiles are bounded to 1 MiB, 4,096 outbounds and 4,096 members per
group; a 1,700-node profile is tested. Connection attempts retain a separate
16-attempt ceiling, so nesting groups does not multiply that work.

```json
{
  "listen_port": 1080,
  "outbounds": [
    {"tag": "direct", "uri": "direct://"},
    {"tag": "blocked", "uri": "block://"}
  ],
  "rules": [{"domain_suffixes": ["blocked.example"], "outbound": "blocked"}],
  "final": "direct"
}
```

`--http-listen 127.0.0.1:8080` and `--mixed-listen 127.0.0.1:8081` add local
listeners. `--api-listen 127.0.0.1:9090 --api-token-file secret.txt` enables
the optional API, requiring a 32-256 character bearer token. `--no-socks`
supports server-only or HTTP/mixed runs. Server entries live in `inbounds`
with `protocol`, `listen`, and explicit `uuids` or `password`/`cipher`;
`cert_file`/`key_file` enable TLS. Changing server listeners or the flow budget
requires restarting; the routing API updates rules/outbounds/groups only.

The initial routing implementation is deliberately separate from the legacy
Windows one-node host script. SDK/packet routing is verified; advanced
multi-outbound Windows route/DNS setup and direct-name resolution after OS DNS
replacement still need host acceptance. A direct-only routing profile is
rejected by CLI TUN bootstrap. Do not present this as complete Windows split
tunneling support. Source/interface matching receives TUN source addresses;
process/interface names require host metadata until OS discovery is added.

Local additions have tests for actual HTTP/SOCKS/TLS payloads, SOCKS5 UDP,
32 UDP associations, 16 SDK connection/close cycles, 32 rejected server clients,
IPv4/IPv6 TCP/UDP packet routing, policy replacement concurrency, DNS cache
isolation, fake addresses, blocking, API credential redaction and pin/name
verification. These are local protocol and lifecycle results, not public-node
Internet coverage for every protocol. Full report coverage remains incomplete.

Local validation for this extension:
- Go tests with the race detector: core/mobile/CLI passed.
- Independent wire suite: 164 tests run, 162 passed and 2 optional cases skipped.
- .NET C ABI smoke: lifecycle, UTF-8 paths, callback lifetime and restart passed.
- Eleven executable cross-builds: amd64/arm64 on Windows, Linux, macOS,
  FreeBSD and OpenBSD, plus Android ARM64, passed.
- Existing Windows policy, dual-family fault/restore and owner lifecycle tests
  passed. These use policy plans/mocks and are not a new live network session.
- Independent client: Xray 26.7.28 / commit 5ca6f4b, installed executable SHA256
  `1d9674327972a21afd4c906a7a72bb0856935aa9e0227c87f34f03d11a88bddf`.
  TLS reference connections pin the synthetic local certificate and name.

The last cross-build/wire/.NET run preceded only the increase in routing JSON
and catalog limits plus rejection of unsupported runtime-budget replacement;
those changes have dedicated tests and a subsequent full race run. CI on the
published revision must be checked independently before claiming its result.
