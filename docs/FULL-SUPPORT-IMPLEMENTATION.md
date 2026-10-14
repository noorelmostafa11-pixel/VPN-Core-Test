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
| ShadowTLS v2 and v3; Shadowsocks with ShadowTLS | Client/server added: verified TLS, v2 challenge, strict v3 handshake/data integrity, standalone/SIP003 Shadowsocks including all three SS2022 ciphers and optional UOT v2 UDP. Independent sing-box 1.14.3 payloads passed both directions with the documented v2 ticket boundary. Non-strict v3 and broader multi-user/SNI options remain pending; see SHADOWTLS.md |
| Hysteria 1 and 2 | Both client/server protocols added: Hysteria 1 v3 TCP/UDP/xplus, negotiated Brutal, verified native TLS and bounded reuse/lifetime; official 1.3.5 payloads passed both directions. Hysteria 2 adds BBR/reno/negotiated Brutal, Salamander/Gecko, native/Chrome and trust/pins/ECH configuration; official 2.13.0 payloads passed both directions. Port hopping, realms, fake TCP and wider authentication/fingerprint options remain pending; see HYSTERIA1.md and HYSTERIA2.md |
| TUIC | v5 client/server added: TLS-exporter authentication, TCP, native/QUIC UDP, fragmentation, direct Full Cone relay, bounded reuse/close and independent sing-box 1.14.3 payloads both modes/directions. Additional congestion selection, uTLS, 0-RTT and per-user passwords remain pending; see TUIC.md |
| AnyTLS | Client/server added: session reuse, bounded padding updates, v1/v2 server framing, verified TLS, TCP and UOT v2 connect/non-connect UDP. Official 0.0.13 client/server payload tests in both directions passed; see ANYTLS.md |
| WireGuard VPN | Client/server added: official encrypted device, protected sockets, bounded reuse/queues/workers, TCP/UDP IPv4/IPv6, PSK, encrypted DNS and native server forwarding. Independent Python Noise_IK/encrypted TCP/UDP/auth/source tests passed. Kernel/public-node and Windows route/DNS acceptance remain separate; see WIREGUARD.md |
| Remote HTTP/HTTPS proxy | Added HTTP CONNECT and verified TLS path; preserve response read-ahead |
| Remote SOCKS4/4a/5 | Added, including SOCKS5 credentials and UDP association; SOCKS4 is IPv4 TCP by specification |
| SSH, Naive, Tor | SSH TCP client and forwarding server added: password/public keys/host identity, protected sockets, shared channel budget, bounded setup/close and independent Paramiko 5.0.0 payload/auth tests. Server supports one username/listener; reverse forwarding remains pending. Naive and Tor remain pending; see SSH.md |
| Snell, Tailcat | Pending: establish exact reference version and protocol scope before implementation |
| Raw TCP, UDP, WS/early data, HTTP Upgrade, gRPC/multi, HTTP2/h2c | Baseline client carriers retained. WS/early-data and HTTP Upgrade server carriers added for VLESS/VMess/Trojan/Shadowsocks TCP; encrypted Vision retains parent carrier layers. Other server carriers remain pending; see SERVER-CARRIERS.md |
| XHTTP modes, metadata, padding and download settings | Baseline implemented scope; preserve original URI semantics |
| HTTP3, QUIC, mKCP, HTTP disguise, simple-obfs, v2ray-plugin | Baseline carriers, distinct from Hysteria/TUIC protocols |
| TLS1.2/1.3, uTLS, ECH, REALITY, legacy XTLS, FinalMask | Baseline implemented scope; certificate verification remains enforced |
| General multiplexing and XUDP/UoT | Partial: VMess/VLESS MUX server framing, concurrent TCP and XUDP destination/Full Cone UDP added with bounded lifetime and independent Xray payload tests. General outbound MUX, cross-parent XUDP migration, smux and additional UOT paths remain pending; see MUX-SERVER.md |
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
| VLESS, Trojan, Shadowsocks server inbounds | Partial: raw TCP with optional TLS (required for Trojan); VLESS/Trojan UDP-over-TCP and VLESS MUX/XUDP. VLESS Vision adds native TLS 1.3, flow authentication, bounded padding/direct transitions and UDP-only MUX/XUDP. REALITY adds interoperable native TLS authentication/data transfer and protected HTTPS fallback; exact target mirroring/ML-DSA remain pending. Hybrid VLESS decryption adds three wire modes, fixed X25519/ML-KEM chains, bounded tickets/replay and optional Vision, using synchronous reusable record buffers. Shadowsocks implements all 35 methods over TCP/native UDP and SS2022 identity chains. Server carriers and wider options remain pending; see VLESS-SERVER.md, REALITY-SERVER.md, VLESS-ENCRYPTION-SERVER.md and SHADOWSOCKS-SERVER.md |
| VMess server inbound | Added raw TCP/optional TLS, TCP/UDP/MUX, AEAD and opt-in legacy alter-ID, AES-GCM/ChaCha/CFB/none/zero, length masking/padding and authenticated lengths. Independent Xray 26.7.28 and V2Ray 4.45.2 payload tests passed; server carriers and remaining upstream options are pending; see VMESS-SERVER.md |
| Other protocol server inbounds | Pending with their corresponding client protocols |
| Reverse proxy / server fallback | Pending authenticated reverse channels and fallback semantics |
| General management API | Added opt-in authenticated loopback stats, selection, route and DNS updates; wider API/events scope pending |
| Statistics / connections / events | Baseline plus SDK flow accounting; richer per-outbound connection inventory pending |
| Go SDK / C ABI / Android AAR / iOS packet hooks / Windows Wintun | Baseline client/packet interfaces retained; Go server startup uses Engine.StartServer and the CLI launches configured inbounds. Mobile/C ABI server startup and broader optional controls still require bindings and acceptance |
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
builds (eleven targets), Windows ABI lifecycle/restart and a clean Windows
shared/Wintun package subsequently passed at published revision
`ff4f4adb889c2d26a26b045f2fda3f1b85c5c46f`. Executable SHA256:
`dc8dc483ca8ab6b696bd140bb83551c0d945ef0a34d6bcce0aeed8a301f67887`.
At the last inspection, CI run `38491127393` had successful source and Android
jobs with other jobs still running. The owner now checks workflows; no final
remote conclusion is inferred. Local payload tests do not establish public-node
Internet or host-route/DNS acceptance.

## 0.5.11 extension

VMess server authentication/body framing and VMess/VLESS MUX servers are added;
see [VMESS-SERVER.md](VMESS-SERVER.md) and [MUX-SERVER.md](MUX-SERVER.md).
Independent Xray clients passed modern TCP, default XUDP, authenticated lengths
and concurrent MUX payloads over verified TLS. Official V2Ray 4.45.2 passed
legacy alter-ID TCP/UDP for every framed security method and unframed TCP zero.
The initial XUDP failure exposed rejection of 42-44-byte legal MUX headers;
the corrected parser has deterministic coverage for all 16 padding lengths.

Initial legacy fixture failures used modern pin fields unavailable in V2Ray 4
and 3,800-byte packets exceeding its 2 KiB buffers. Fixture trust now uses the
generated CA with name verification, and legacy reference payloads fit that
documented buffer. The core still transfers atomic 60,000-byte UDP payloads in
Go tests. The initial direct-MUX owner test launched its worker outside the
engine and observed admission before the helper joined; it now uses engine
ownership. Failure logs are retained rather than counted as successes.

Core/mobile/CLI race tests and vet passed, including concurrent relay,
protection failure, replay limits, corruption, nonce exhaustion and shutdown.
Final combined regression, portable builds and clean package checks are recorded
separately below. Remote workflow inspection is left to the owner as requested.
Full report scope and varied-node Internet/OS host acceptance remain incomplete.

The first full 181-case regression run failed one existing ShadowTLS v2 client
case with enabled TLS backend tickets. Its current/previous-write challenge
could advance past Finished before the client switched. Read-ahead alone and
disabling unused resumption both failed and were reverted. The final correction
authenticates and includes bounded residual records before the initial switch;
see SHADOWTLS.md for the setup timing and remaining reference boundary. The
expanded independent standalone/SIP003 v2 fixture passed 64 sessions each after
this change. This is a production ShadowTLS correction; the original failure
is retained separately from subsequent validation.

Final combined wire validation passed: 181 tests run, 179 passed and the two
existing optional cases skipped. Full core/mobile/CLI race tests and vet passed
after the production correction; final timestamp/idle-expiry assertions also
passed separately under the race detector. Eleven final executable cross-builds
passed: Windows/Linux/macOS/FreeBSD/OpenBSD amd64 and arm64 plus Android arm64.
The clean Windows shared/Wintun package and ABI result are recorded with the
published source checkpoint. No remote workflow conclusion is inferred.

## 0.5.12 extension

Shadowsocks servers now implement all 35 existing cipher methods over native
UDP, plus SS2022 TCP with fixed AES identity chains, optional verified TLS,
bounded authentication/replay/session state and owner shutdown. SS2022 inside
ShadowTLS supports TCP and explicit UOT v2 over both versions. Independent
sing-box 1.14.3 tests transfer data in both directions and exercise identity
chains; see [SHADOWSOCKS-SERVER.md](SHADOWSOCKS-SERVER.md).

Authenticated UDP migration preserves the direct relay source socket and
captures source metadata per queued request. Routed proxy cache entries include
source IP and route tag, with explicit block rejection before reuse. Stopped
relays keep their replay tombstone without refreshing it on rejected traffic.
Queues, peer state and relay connections retain shared limits; disabling native
UDP creates no UDP listener/workers.

Initial TLS/transport fixture omissions and a random-padding corruption-offset
panic were corrected in tests. Production fixes address rejection of the exact
UOT virtual port-zero destination, repeated `table` permutation construction
per UDP packet, and Windows automatic TCP/UDP port collisions. The table cache
is lazy and per-codec; its pressure test keeps the original deadline and sizes.
Automatic port selection retries at most eight candidates; explicit occupied
ports still fail and roll back TCP. Failure logs and deterministic regressions
are retained in the local acceptance record. These do not establish varied
public-node Internet, Windows route/DNS recovery or mobile host acceptance.

Final combined independent wire validation passed: 184 tests run, 182 passed
and two existing optional cases skipped. Core/mobile/CLI race tests and vet
passed after the final dual-bind correction. The same full suite retains the
older protocol/cipher/carrier/client tests and Hysteria/SSH/WireGuard/AnyTLS/
TUIC/ShadowTLS reference payloads. Targeted `table` pressure/concurrency and
real-socket dual-bind recovery/ceiling/rollback checks passed separately.
The owner requested immediate source publication and delegated remaining builds
and package/ABI checks to the workflow. The owner subsequently clarified this
means only final full builds: normal local race/wire checks continue. The local portable matrix was stopped;
no completed 0.5.12 matrix or clean Windows package/ABI result is claimed.
Previous 0.5.11 packages remain preserved. Workflow review remains with the
owner, without waiting for or polling its result.

## 0.5.13 extension

VLESS Vision servers are implemented over native TLS 1.3. Flow/UUID/addon
validation precedes forwarding; direct transitions preserve record boundaries
and require observed inner TLS 1.3. Empty-flow UDP retains packet framing,
and Vision listeners allow only UDP MUX subflows so TCP cannot bypass their
flow requirement. No optional feature workers are added; see
[VLESS-SERVER.md](VLESS-SERVER.md).

Six targeted Go race tests passed real TCP/UDP and inner TLS payloads, owner
loss, malformed addons, policy rejection, split direct transitions and
half-close. Two independent official Xray 26.7.28 cases passed plain/inner-TLS/
XUDP transfers and missing-flow rejection. The initial launcher omitted the
tests module path and failed to import; it was corrected before the payload
run. Full core/mobile/CLI race tests and vet subsequently passed.

The workflow now installs hash-pinned Xray 26.7.28 reference executables into
RUNNER_TEMP for actual wire tests, excluded from runtime packages. The Windows
download/hash/executable-version path was checked locally. Final full matrix/
package builds remain delegated to the workflow; local checks continue, with
no waiting or polling of remote runs. Server REALITY, VLESS encryption and
server carriers remain next work; broader report scope is still incomplete.

Final combined independent wire validation passed: 186 tests run, 184 passed
and two existing optional cases skipped. Core/mobile/CLI race tests passed in
55.621 seconds and vet passed. The test-only pinned Windows Xray installer also
passed archive hash and executable version verification. No local final full
platform/package build or remote workflow conclusion is claimed.

## 0.5.14 extension

VLESS REALITY servers implement native TLS 1.3 authentication, TCP/UDP/MUX and
optional Vision, listener-local bounded replay protection and one explicit
protected fallback. Fragmented ClientHello records and extra bytes are retained
unchanged. Exact target handshake/record mirroring, ML-DSA server signatures and
wider upstream options remain pending; see [REALITY-SERVER.md](REALITY-SERVER.md).

Initial browser handshakes failed because normal TLS declined the fixed
Ed25519 signature required by REALITY. The authenticated native TLS adapter now
sets the parsed signature-selection list, preserving original transcript bytes.
The existing native REALITY client also lacked serialized hello bytes; it now
serializes the same native hello before signing. Initial failures are retained
separately. Seven client profiles passed with/without Vision, plus authentication,
replay limits, fragmentation, fallback HTTPS bodies and owner/protection checks.
Official Xray 26.7.28 passed plain and verified inner-TLS TCP plus XUDP, in both
flow modes. Full core/mobile/CLI race tests passed in 59.178 seconds; vet passed.

Final full platform/package builds remain delegated to the workflow. Normal
local checks continue without waiting for or polling remote runs. Local payload
acceptance does not establish complete camouflage, varied-node Internet or live
Windows route/DNS recovery. VLESS encryption and server carriers are next.

Final combined independent wire validation passed: 187 tests run, 185 passed
and the two existing optional cases skipped, in 189.443 seconds. The full suite
retains older client/carrier/cipher and newly added server payload coverage.
No final local platform/package build or remote workflow result is claimed.

## 0.5.15 extension

VLESS hybrid encryption servers add the three existing wire modes, fixed
X25519/ML-KEM-768 private-key chains, authenticated ephemeral exchange, AES-GCM/
ChaCha negotiation, optional Vision and bounded 0-RTT tickets/replay state.
Expired state is reclaimed lazily; no cache maintenance worker is created.
Client/server records now run synchronously with lazy reusable direction-local
buffers instead of two additional encryption workers and queues. Client ticket
identities include their endpoint/security/name/path, isolating listeners that
share keys. Vision direct transitions peel only VLESS AEAD, preserving the
parent TLS/REALITY/carrier and full-random header masking. See
[VLESS-ENCRYPTION-SERVER.md](VLESS-ENCRYPTION-SERVER.md).

Targeted Go race checks passed modes, fixed chains, large atomic UDP, repeated/
parallel transfers, verified inner TLS/Vision, listener ticket isolation,
concurrent replay rejection, capacity/expiry, corrupt offers/records, protection
and owner loss, cancellation, ChaCha resumption, nonce-boundary rekey and
half-close. A fixture initially used a nonexistent hook field and failed to
compile; it now supplies construction-time hooks. Failed evidence is retained.
Official Xray 26.7.28 passed five configurations with plain/inner-TLS TCP and
UDP/XUDP, static ML-KEM, 1/0-RTT, native TLS and Vision. Full core/mobile/CLI race
checks passed in 60.098 seconds; vet passed. Combined wire results follow below.

The first full 188-case wire run failed one wrapped encrypted-Vision inner-TLS
case, and six standalone repetitions exposed a second full-random case. Normal
TLS/data tests passed, but rejecting command 2 at this boundary intermittently
stalled reference clients. The corrected layer-aware transition ends VLESS
record encryption while retaining parent TLS/carriers and random header CTR.
Six unchanged reference repetitions subsequently passed, alongside deterministic
fragmented-header and layer-boundary race checks. The original failures are
retained and are not counted as an all-pass regression result.

Final full builds remain delegated to the workflow, without waiting or polling.
Server carriers, stale-ticket connection retry and wider report options remain
open; loopback acceptance does not establish varied public-node Internet or
live Windows route/DNS recovery.

Final combined independent wire validation passed: 188 tests run, 186 passed
and two existing optional cases skipped, in 202.344 seconds. The hybrid fixture
now also passes encryption with REALITY/Vision and verified inner TLS. Final
core/mobile/CLI race checks passed in 66.893 seconds and vet passed after the
layer-boundary correction. Only source is published; no final local platform/
package build or remote workflow result is claimed.

## 0.5.16 extension

VLESS/VMess/Trojan/Shadowsocks TCP servers add optional WebSocket and HTTP
Upgrade, with verified TLS, explicit bounded WS early data, path/host policy,
preserved prefetched bytes and masked/unmasked frame roles. Existing workers,
flow admission, routing and shutdown are reused; no HTTP pool/library or
heartbeat worker is added. HTTP headers/frame/control/no-progress limits reject
unbounded input before proxy forwarding. Encrypted Vision peels only its AEAD
while retaining carrier/outer security; pure Vision and REALITY combinations
with these carriers remain explicit limits. See [SERVER-CARRIERS.md](SERVER-CARRIERS.md).

Targeted Go race checks passed four protocols/two carriers, repeated TCP,
large atomic UDP-over-stream, TLS, early data/escaping/coalescing, fragmented
mask/control frames, malformed settings/requests/limits, incomplete owner loss
and native encrypted Vision with real inner TLS. SDK/encryption wrapper metadata
now preserves negotiated TLS information. Initial test fixture credential fields
and a missing metadata unwrap were corrected; failed runs remain recorded.
Official Xray 26.7.28 passed both carrier matrices, plain/inner-TLS encrypted
Vision and XUDP. Its Trojan first payload exceeded its fixed buffer before any
header reached the project server. The fixture now authenticates a small first
exchange before its unchanged large body/deadline checks; no core restriction
or payload limit was weakened. Combined local results follow below.

Further server carriers, wider listener options and report items remain open.
Only final full builds are delegated to the workflow; local checks continue,
without waiting or polling remote runs. No all-platform/public Internet or
Windows host recovery acceptance is inferred.

Final combined independent wire validation passed: 190 tests run, 188 passed
and two existing optional cases skipped, in 223.859 seconds. Full core/mobile/
CLI race checks passed in 65.527 seconds; vet passed. Native encrypted carrier
inner-TLS/metadata cases and independent Xray matrices passed before that full
run. No final local platform/package build or remote workflow result is claimed.
