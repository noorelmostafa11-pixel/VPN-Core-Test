# Four remote VPN protocols

Owner-directed scope change, 2026-10-17. Initial source parent:
`8e4c4329e1e7f466070b942c8304301e1c91f9f4`; integrated publication parent:
`9278723cb56199c94b0161ec8613a45e5820ce64`. Only Shadowsocks (including SS2022),
Trojan, VLESS and VMess remain remote VPN protocols. The former all-protocol
migration plan is cancelled. Unpublished Hysteria1 work was preserved privately
outside Git before being removed from the working source.

## Removal and retained services

SSH, Hysteria2, WireGuard and MASQUE proxy source/config/protobuf handlers and
dedicated tests are removed, together with Hysteria2/MASQUE transports, validator
hooks, user-management cases and WireGuard CLI key command. Hysteria1 is not
included; TUIC, AnyTLS and ShadowTLS will not be ported under this scope.

Remote HTTP/SOCKS clients, SOCKS4/4a outbound additions and their tests are
removed. HTTP/SOCKS remain local ingress only. Original shared protocol codecs,
account/configuration DTOs and protobuf messages used by the local ingress and
the unchanged baseline fixture remain; they cannot instantiate a remote client.
The original SOCKS schema/config builder is restored exactly from pinned
upstream after removing its added remote-client fields.

Local SOCKS/HTTP/mixed/TUN and tunnel ingress, DNS/fakeDNS, direct/block/loopback,
routing, policy, statistics, dispatcher and the four protocols' transports remain.
All classic SS cipher additions, SS2022 and isolated legacy VMess body/header
support are retained. No four-protocol codec, cryptography, account runtime,
TLS/REALITY implementation or routing implementation is rewritten in this batch.

XHTTP/HTTP3 still uses shared BBR/Brutal congestion control. Its 12 source/test
files move from the removed Hysteria tree to `transport/internet/quic/congestion`;
their contents are identical to the parent except package import paths. Existing
debug environment names and attribution are retained. TUN's platform adapter
libraries and QUIC packet camouflage names do not register a WireGuard VPN.
Dependencies remain pinned: tidy found no removable module; its unrelated
direct/indirect classification and line-ending changes were not applied.

## Input and security

URI, versioned JSON-node and Go ResolveNode accept only `ss`, `trojan`, `vless`
and `vmess`. Full JSON retains local service selectors but excludes removed
remote protocols. Negative checks cover the complete registry, upper/lowercase
removed URI/JSON/Go nodes, removed full-config selectors and direct Go attempts
to instantiate HTTP/SOCKS clients. Rejection precedes networking and has no
protocol fallback. Resolver errors do not echo credentials.

Explicit TLS node trust metadata (`pcs`/`pinsha256`/`pinnedPeerCertSha256` and
`vcn`/`verifyPeerCertByName`) now maps to the original TLS settings for the four.
The original verifier validates it; absent pins keep original trust defaults.
Conflicting/invalid pins, trust data on plaintext and insecure verification
bypass remain rejected. Full JSON/protobuf TLS policy is unchanged.

The common live matrix exercises six variants (VLESS, VMess, Trojan, classic
SS AES256-GCM, added SS AES192-GCM and SS2022 AES128), each through JSON, URI,
JSON-node and Go. All 24 endpoint pairs require exact120003-byte fragmented TCP
and UDP32/1400/3800-byte payloads with destination/source boundaries. Trojan uses
a pinned synthetic TLS certificate in every input format. Owned echo workers
are closed and joined. These are loopback peers, not Internet acceptance.

The first matrix fixture omitted Xray's required explicit permission for private
loopback targets; its original default protection blocked connections and the
run reached its unchanged120s test timeout. The fixture now permits only
127.0.0.1/32, without changing production policy. A subsequent self-signed test
using insecure=true was correctly rejected by original TLS validation; explicit
pin metadata replaced it, without permitting insecure TLS. Both failed logs are
retained privately. The corrected focused race checks pass core4.301s/conf3.939s.
No payload assertion was removed or protocol failure retried unchanged.

## Frozen source and validation

The completed broad race/scenario checks used1142 Go/protobuf/module paths,
fingerprint `5894e00fc771a06b3966c0f9b65d90227a6474e77b4602390c2784f676ce0611`.
The remote branch had acquired packaging commits5fcfbb96/33f43a55 and isolated
Hysteria1 primitives9278723c. Integration preserves the packaging tool, asset
manifest, ignore entry and documentation, and removes the Hysteria1 primitives
under the owner's new scope. All1142 already tested source paths remain
identical; the only two additional source files are tools/package/main.go and
its unit tests. Those pass race checks separately after integration.

Final source:1144 Go/protobuf/module paths. SHA256 of sorted Git-blob-ID/path
lines: `6caceeefe193876c30a8b864ea9cd79db90a8274c5d3b99f0dc5794dd27ef35b`.
The shared original fixture remains byte-identical, SHA256
`f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.

Go1.27.1 Windows/amd64, GCC16.2 for race:

| Check | Result |
| --- | --- |
| Full affected race suite | PASS: conf11.896s,serial7.513s,core280.591s,main11.405s; SS18.938s,SS2022 7.734s,Trojan7.531s,VLESS encoding7.378s,VMess6.783s/AEAD250.664s/encoding40.015s/outbound3.181s |
| Local ingress and retained affected transport race suites | PASS: SOCKS5.802s,HTTP3.479s,XHTTP7.676s,QUIC20.311s,BBR2.618s,Brutal2.863s,HTTP2 17.594s,Sudoku retained VLESS cases152.013s |
|17 retained original runtime scenarios | PASS race240.357s: SS TCP/UDP/Mux, VMess TCP/UDP/Mux/length authentication, VLESS/TLS/Vision/REALITY, local SOCKS conformance |
| Shared original fixture on pinned upstream | PASS race7.384s; fork runs the identical fixture in full conf suite |
| URI/description fuzz | PASS20018/20000 executions,2 workers each,51.758s/22.600s |
| Post-integration packaging plus four-protocol race | PASS packaging6.022s,core5.747s,conf5.391s |
| Post-integration whole-tree compilation | PASS go test ./... -run '^$'; compilation only |
| Whole-tree vet before and after integration | PASS exit0, no diagnostics |
| Final same-source CLI builds | PASS Windows/amd64,Linux/amd64,Darwin/arm64; CGO0,trimpath,stripped |
| Final Windows CLI configuration execution | PASS8 URI/node profiles and14 excluded-protocol rejections; version9278723-dirty |
| Final CLI dependency audit | No excluded proxy package or WireGuard device runtime linked |

Packages listed as having no test files compile; they do not represent separate
runtime tests. The preserved packaging tests use synthetic local HTTP assets;
the packaging command, asset downloads, ZIP creation and distribution are not
run. This is a union of completed affected checks and unchanged-source proof,
not a single successful whole-tree runtime test command.

Final private Windows executable:34062848bytes, SHA256
`9a63af3efda5b0ab076447f5a47cea85ce56dc8850d543db7c59dd3296d2b7ec`.
Equivalent previous Go1.27.1/CGO0/trimpath/stripped Windows build:35952640bytes,
SHA256 `7df7b52c99b5418568b146aae9ff121acbadecc14e60b902b9671af65f14f17a`.
Reduction:1889792bytes (5.26%); no speed or memory improvement is claimed.
Linux output:33624224bytes, SHA256
`772650ef08f2b279812de5a68945b6d4395aadce7a7695e81e1a05f540011f9f`.
Darwin output:32156530bytes, SHA256
`35dd98d381a7dc17c6258d2560662fe5f722725f5dec9dd2ef7ea498e58440a6`.
The version identifies the tested parent plus edits, not a future clean commit.

Local evidence, snapshots, synthetic certificates and binaries stay outside Git
in the private report-review directory under `xray-four-protocol-`. Source hashes
are checked again before publication. No executable or package is committed.

Runtime evidence is Windows/amd64 only. Foreign CLI compilation does not prove
foreign runtime, platform packaging, TUN privileges, mobile/SDK linkage or
private-node/Internet compatibility. The known unchanged external TLS ECH test
failure is not relabeled green; selected offline checks are not the entire test
tree. Main, releases, owner README, workflows and compatibility runners remain
unchanged; no workflow is dispatched or monitored.
