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
| ShadowTLS v2 and v3; Shadowsocks with ShadowTLS | Client/server added: verified TLS, v2 challenge, strict v3 handshake/data integrity, standalone/SIP003 Shadowsocks and optional UOT v2 UDP. Independent sing-box 1.14.3 payloads passed both directions with the documented v2 ticket boundary. Embedded SS2022, non-strict v3 and broader multi-user/SNI options remain pending; see SHADOWTLS.md |
| Hysteria 1 and 2 | Both client/server protocols added: Hysteria 1 v3 TCP/UDP/xplus, negotiated Brutal, verified native TLS and bounded reuse/lifetime; official 1.3.5 payloads passed both directions. Hysteria 2 adds BBR/reno/negotiated Brutal, Salamander/Gecko, native/Chrome and trust/pins/ECH configuration; official 2.13.0 payloads passed both directions. Port hopping, realms, fake TCP and wider authentication/fingerprint options remain pending; see HYSTERIA1.md and HYSTERIA2.md |
| TUIC | v5 client/server added: TLS-exporter authentication, TCP, native/QUIC UDP, fragmentation, direct Full Cone relay, bounded reuse/close and independent sing-box 1.14.3 payloads both modes/directions. Additional congestion selection, uTLS, 0-RTT and per-user passwords remain pending; see TUIC.md |
| AnyTLS | Client/server added: session reuse, bounded padding updates, v1/v2 server framing, verified TLS, TCP and UOT v2 connect/non-connect UDP. Official 0.0.13 client/server payload tests in both directions passed; see ANYTLS.md |
| WireGuard VPN | Client/server added: official encrypted device, protected sockets, bounded reuse/queues/workers, TCP/UDP IPv4/IPv6, PSK, encrypted DNS and native server forwarding. Independent Python Noise_IK/encrypted TCP/UDP/auth/source tests passed. Kernel/public-node and Windows route/DNS acceptance remain separate; see WIREGUARD.md |
| Remote HTTP/HTTPS proxy | Added HTTP CONNECT and verified TLS path; preserve response read-ahead |
| Remote SOCKS4/4a/5 | Added, including SOCKS5 credentials and UDP association; SOCKS4 is IPv4 TCP by specification |
| SSH, Naive, Tor | SSH TCP client and forwarding server added: password/public keys/host identity, protected sockets, shared channel budget, bounded setup/close and independent Paramiko 5.0.0 payload/auth tests. Server supports one username/listener; reverse forwarding remains pending. Naive and Tor remain pending; see SSH.md |
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
| URL testing / healthy-node selection | Added opt-in url_test groups: verified HTTPS/status/body, multiple sites, fastest verified member, protected shared budget, at most 16 probes/round and four concurrently, five-second minimum round cadence, gradual catalog scan and redacted health API. Local 1,700-node, cancellation/reload/body/trust tests passed; public-node and UDP acceptance remain separate; see URL-TESTING.md |
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

## 0.5.4 extension

Hysteria 2 clients and servers and SSH TCP outbounds are implemented; see
[HYSTERIA2.md](HYSTERIA2.md) and [SSH.md](SSH.md). No application files or private
profiles are included. Binary builds now preserve license snapshots and hashes
in their build manifest; packaging uses those exact snapshots. Mobile staging
includes every newly patched Hysteria/QUIC module.

The first complete Hysteria wire run (165 tests) had one mKCP loss/reordering
failure while cross-builds ran concurrently. Its standalone rerun passed.
That initial run is retained as a failure, not counted as an all-pass result.
The final combined SSH/Hysteria wire run passed: 167 tests run, 165 passed,
two existing optional cases skipped. The official Hysteria fixture passed six
TCP/UDP client/server/obfuscation combinations; Paramiko tests passed SSH
payloads and authentication/host-key rejection. Full Go race tests and vet
passed. Eleven final executable cross-builds passed (Windows/Linux/macOS/
FreeBSD/OpenBSD amd64 and arm64, plus Android arm64). Windows C ABI library
and binary packaging built successfully; license snapshots/hashes were verified.
These are local results; remote CI and Android AAR/iOS bindings require their
own confirmation. The stripped Windows executable is 17,406,464 bytes;
the previous 0.5.3 build was 15,208,448 bytes. No throughput/latency claim is
inferred from size or passing tests.
The report's remaining items still require implementation; this extension does
not establish full report coverage or Xray/sing-box parity.

Published 0.5.4: `9f2e32f01ccb9069007295922c0dd153d4862ac4`.
Its CI passed Windows/Linux/portable/Android but failed macOS on large UDP
payloads. Apple defaults to a 9216-byte UDP send space. Fix
`2898066e32e6e17a437237be09b55333b51b3f5e` sizes only the affected sockets'
buffers, with no system sysctl change. CI run `38353373600` completed
successfully on the exact fix: all six jobs, including macOS and Android AAR.
The earlier failing run is retained as a failure. iOS bindings still require
macOS/Xcode/host entitlements and are not inferred from the Android result.

## 0.5.5 extension

WireGuard client/server implementation and bounded device lifecycle are
described in [WIREGUARD.md](WIREGUARD.md). Independent encrypted protocol
payload/authentication/source-prefix tests passed locally. This addition does
not change the original OS/mobile TUN packet loopback policy. Full local
validation passed: race tests for core/mobile/CLI, vet, 170 independent wire
tests (168 passed, two existing optional skips), eleven executable cross-builds,
Windows C ABI lifecycle/restart smoke and binary packaging/license hashes.
New tests include repeated connections, PSKs, encrypted DNS and bounded
admission/close. The stripped Windows executable is 17,908,736 bytes.
Publication and its remote CI are checked separately. Other pending report entries
remain pending; no application files or private profiles are deliverables.

Published WireGuard: `67c0430831b03c628c002cf50597fbd23083ff5e`. Its CI passed
Windows/Linux/portable/Android but failed two one-second macOS WireGuard setup
tests. Fix `c264de05593ffab16f0e284122b01591f10ee7a4` selects peer endpoints
sequentially, avoiding same-key handshakes roaming the server to a losing
socket, and uses a normal five-second fixture setup budget; explicit 100 ms
authentication-rejection tests remain. CI run `38359427401` completed successfully
on the exact fix: all six jobs, including macOS and the Android AAR. The earlier
WireGuard run remains recorded as a failure, not an all-pass result.

## 0.5.6 extension

Project-authored AnyTLS clients/servers, session reuse, padding updates and
UOT v2 are described in [ANYTLS.md](ANYTLS.md). Official reference TCP/UDP
tests passed in both directions. Full local validation passed: race tests for
core/mobile/CLI, vet, 172 wire tests (170 passed, two existing optional skips),
eleven executable cross-builds, Windows C ABI lifecycle/restart and binary
packaging. Publication and its CI are checked separately. Other pending report
entries remain pending.

## 0.5.7 extension

TUIC v5 clients/servers and ShadowTLS v2/v3 with Shadowsocks and optional UOT v2
are implemented; see [TUIC.md](TUIC.md) and [SHADOWTLS.md](SHADOWTLS.md). Full
report coverage remains incomplete; their additional options and all other
pending entries remain explicit.

Local validation passed: full core/mobile/CLI race tests and vet, eleven
executable cross-builds, Windows C ABI lifecycle/restart and binary packaging.
The combined wire run executed 173 tests with 170 passed and three optional
skips. The skipped Xray reference class was then run separately against the
installed independent Xray and passed its VLESS/Trojan/SS payload cases; the
two old optional skips remain. New sing-box 1.14.3 TUIC and ShadowTLS payload
cases passed. Initial reference failures involving Windows UDP buffer limits
and ShadowTLS v2 TLS tickets remain documented in the respective protocol
records. Local tests are not public-node/host-route Internet acceptance.

The stripped Windows executable is 18,263,552 bytes, compared with 18,010,624
for the previous build. No throughput/latency improvement is inferred from
tests or binary size. The local pre-publication build records a dirty tree;
it is not represented as a clean published release. Publication and CI require
their own confirmation.

Remote main advanced independently to
`d3442fea7d65ee02e4e807b6c457c5cf2f738d19` while this work ran: the owner's
commit adds a manual node-acceptance workflow only. It is preserved without
modification; the original protocol-source baseline remains `63cc65b...`.

Published 0.5.7 and its strict-server/fixture follow-ups are included in
`9c974a24009059ad3743ee846d029ea17b012d46`. The initial strict-version unit
fixture used an incorrect SessionID offset and failed locally; it was
accidentally committed before its result was checked. The fixture correction
passed locally. CI run `38383029494` completed successfully on that exact final
revision: all six jobs, including macOS, Windows, Linux, portable builds and
Android AAR. The superseded runs were cancelled, not reported as passing.

## 0.5.8 extension

SSH forwarding servers now support explicit host keys, password and authorized
public keys, shared channel limits, physical/channel idle ownership, protected
routing and joined close; see [SSH.md](SSH.md). Independent Paramiko clients
passed payload/authentication/channel-rejection tests with both authentication
methods. Full local validation passed: race tests for core/mobile/CLI, vet,
175 wire tests (173 passed, two existing optional skips), eleven executable
cross-builds, Windows C ABI lifecycle/restart and binary packaging. The stripped
Windows executable is 18,358,272 bytes. This pre-publication package records a
dirty tree; publication and its exact CI are confirmed separately.

Remaining report entries still require implementation and their own acceptance.
No application files, private profiles or private keys are repository artifacts.

Published SSH server: `9564b422a013324e82b377fb49c2a4916d1bc975`.
CI run `38385999782` completed successfully on that exact revision: all six
jobs, including Windows/Linux/macOS, portable builds and the Android AAR.

## 0.5.9 extension

Optional HTTPS/body-verified health groups and redacted health controls are
implemented; see [URL-TESTING.md](URL-TESTING.md). Tests cover blocked responses,
certificate/body rejection, site fallback, 1,700-member scheduling bounds,
manual throttling, local protection failure and reload/owner lifetime.
Full core/mobile/CLI race tests and vet passed. The first full wire run failed
the existing eight-flow mKCP loss/reordering fixture; its isolated rerun passed.
Review found that the reference sender reversed its entire pending backlog
before choosing a flight, potentially starving older missing packets, and did
not apply the advertised receive window. The fixture now bounds/reorders the
oldest 64 eligible segments; data sizes, eight flows, loss and duplication
remain unchanged. No production mKCP code was modified. A subsequent combined
wire run passed 175 tests (173 passed, two old optional skips); that run preceded
the final oldest-flight refinement, whose complete five-case mKCP rerun passed
separately. The initial failure remains recorded as a failure, not an all-pass.

Eleven portable executable builds, Windows C ABI lifecycle/restart and binary
packaging/license hashes passed. The stripped Windows executable is 18,403,840
bytes. The local pre-publication package records a dirty tree; publication and
exact remote CI are confirmed separately. Remaining report entries are still
pending.

## 0.5.10 extension

Hysteria 1 binary v3 clients/servers now support TCP/UDP, xplus, negotiated
Brutal rates, verified native TLS, protected routing and bounded reuse/close;
see [HYSTERIA1.md](HYSTERIA1.md). The official 1.3.5 executable passed TCP/UDP
both directions with and without obfuscation after correcting the advertised
DATAGRAM limit for old peers. Its initial UDP failure is retained locally.
Full core/mobile/CLI race tests and vet passed; a later Hysteria-only race run
also covers the final reusable xplus receive buffer.

Regression verification exposed two fixture issues. The ShadowTLS fixture
waited for the project's SOCKS listener but not the independent server; it now
waits for both before the first payload without retrying application data. A
176-case run failed two ShadowTLS cases before that correction; its standalone
rerun passed. A following 176-case run passed ShadowTLS but failed mKCP's
eight-flow loss/reordering case. The earlier mKCP oldest-flight fix did not
address the receiver loop sending a new aggregate flight after reading only
one incoming packet, which could build a stale ACK/retransmission backlog.

The mKCP fixture now drains at most 256 incoming packets before transmitting,
and gives its single eight-flow socket a bounded 1 MiB receive buffer. All
intentional drop/duplicate/reordering rules, MTU, eight flows and 190,001-byte
payloads are retained. Merely increasing buffers failed. A temporary production
socket-buffer change was reverted: with the corrected fixture, the original
production mKCP code passed three eight-flow repetitions and all five mKCP
cases (seven test invocations total). No production mKCP code is changed by
this extension. The unsuccessful diagnostic runs are retained; these findings
are not a diagnosis of every public-node failure.

Remote main advanced independently to `84cb1865cc9de26d913d3f542d5fd43362036eed`
after the owner merged the prior Go work and refreshed the public guides. Its
documentation and manual node workflow are preserved in the feature branch;
this implementation does not modify main. Remaining report entries still
require implementation and their own acceptance. Final combined tests,
packaging, publication and exact-head CI are recorded separately.

The final combined wire run passed 176 tests: 174 passed and the two existing
optional cases skipped. The initial run omitted AnyTLS because the reference
path pointed to an executable instead of its directory; those two cases passed
separately and were included in the final combined result above. Portable
builds, Windows ABI/package output and exact published-head CI still require
their own recorded results; local payload tests do not establish public-node
Internet or host-route/DNS acceptance.
