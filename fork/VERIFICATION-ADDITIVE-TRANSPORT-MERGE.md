# Reviewed four-protocol transport additions

Reviewed on 2026-10-18, starting from the owner's published
`cdc8e0cc3cd6d12a748f0b128aec316f1e74c642`. Candidate:
`feature/tcp-mkcp-additive-review-20261017` at
`ea89e85630f611c3a80ad198364b832150941d49` (29 commits).
The owner's historical QUIC test-prefix initialization fix is retained.

This record supersedes the candidate's historical `REVIEW-*.md` execution
status for the source and checks identified here. It does not turn those
historical parser-only checks into runtime evidence.

## Scope and corrections

Remote protocols remain Shadowsocks/SS2022, Trojan, VLESS and VMess. Added
connection metadata selects the existing TCP HTTP camouflage, mKCP seed/header
and numeric settings, WS/HTTPUpgrade headers and early data, HTTP2 method,
headers and health settings, gRPC settings, independent XHTTP download settings,
and explicit bounded legacy-QUIC flow/BBR/Brutal settings. Original transport
defaults remain selected when metadata is absent.

Explicit URI-list/Base64 subscriptions and versioned JSON node arrays use the
same four-protocol resolver. New file extensions require their explicit formats
for directory scanning; the original default directory filter is unchanged.
The review supplied the missing in-memory loaders for `subscription`, `sub`,
`subjson` and `node-list`, and included them in merged configuration output.
Multiple subscription files now scope generated tags by one-based file position
before the original merge rules run. A regression reproduced four imported nodes
becoming two through colliding generated tags. Single-file tags and original
JSON/YAML/TOML/URI/node merging remain unchanged.

Issues found and corrected before integration:

- The plugin importer incorrectly treated default `v2ray-plugin` connections as
  raw WS. [Upstream main.go at e9af1cdd](https://github.com/shadowsocks/v2ray-plugin/blob/e9af1cdd2549d528deb20a4ab8d61c5fbe51f306/main.go)
  defaults to mux=1 and changes the stream framing. The supported subset now
  requires explicit `mux=0`, preserves the original `cloudfront.com` host
  default, and rejects multiplexed/default plugin modes. This is TCP plugin
  compatibility, not execution of arbitrary SIP003 plugins.
- Raw byte comparisons of nested TypedMessage protobufs made new header-map
  parity tests fail according to map serialization order. The added tests now
  normalize embedded protobuf serialization and still compare every field.
  The production serializer and original preservation fixture are unchanged.
- Explicit early-data rewriting rejected malformed query encodings instead of
  silently discarding query fields. Profiles without the new selector retain
  their original interpretation.
- Runtime race checks found receive-buffer release/read overlap in mKCP,
  shared packet-header counters, WS deferred connection publication/close,
  and concurrent gRPC Send/CloseSend. Existing locks were extended or narrowly
  added around these ownership transitions, with no cipher or wire-format change.
- HTTPUpgrade discarded application bytes read ahead with the HTTP request.
  It now detaches those bytes before leaving the header-limited reader. Its
  client also retains response read-ahead bytes and waits for application data
  on a nonempty read, rather than returning `(0, nil)` after a bare 101 response.
  This fixes the reproduced SS2022/HTTPUpgrade early-data disconnect.

The direct mKCP, packet-header, gRPC and HTTPUpgrade regression tests were also
run against pinned original Xray `701af60772cda123492f86e383e1fdba066614a9`.
They reproduced the races, duplicate SRTP sequence numbers, repeated/overlapping
CloseSend, discarded early bytes, and empty first application read. Their
corrected fork results are recorded separately below; failing evidence is kept.

## Runtime coverage and fixture boundaries

- 120 protocol/carrier/input cases: five variants (four families plus SS2022),
  eight carriers, URI/JSON-node/Go input. TCP payloads contain 120003 exact bytes
  in fragments; supported UDP endpoints check three packet sizes and sources.
  For Shadowsocks over mKCP/legacy QUIC, 18 cases are TCP-only: native Shadowsocks
  UDP requires its own UDP endpoint, while these carriers already occupy the port.
- 25 split XHTTP download/input cases across URI, node, Go, Base64
  subscription and JSON node-list input. Separate upload and TLS download HTTP
  peers enforce different methods, Host and headers. Download trust uses an
  explicit synthetic certificate pin; a wrong-pin case must reject. SS UDP is
  separately served at the advertised endpoint, not mislabeled as XHTTP UDP.
  These HTTP/TLS frontends forward to a paired fork XHTTP backend; this is not
  an independent implementation of XHTTP framing or the four proxy protocols.
- Independent WS/HTTPUpgrade/HTTP2 peers inspect imported headers, authority,
  early bytes or method and exchange exact application payloads.
- The real upstream v2ray-plugin at `e9af1cdd2549d528deb20a4ab8d61c5fbe51f306`
  serves six TCP interoperability cases: classic SS and SS2022 through URI,
  JSON-node and Go input. `XRAY_V2RAY_PLUGIN_REFERENCE` points explicitly at the
  private test executable; production never invokes it. Without this variable
  that optional reference test explicitly skips.
- Ten independent legacy QUIC client/server cases cover Reno flow overrides,
  all three BBR profiles and unequal explicit Brutal rates. Existing independent
  packet/TLS/lifecycle and loss/reorder/duplicate checks remain in the suite.

Initial runtime fixtures exposed two setup mistakes that are retained in the
private failure logs: incompatible padding ranges on opposite XHTTP legs, and
trying to bind native SS UDP on the same port as a UDP carrier or omitting the
public SS UDP endpoint behind HTTP frontends. The fixtures now express the
actual supported endpoints. These corrections do not change production settings
or lower payload, packet, pin, timeout or race assertions.

## Same-source validation

Go 1.27.1, Windows/amd64, GCC 16.2 for race checks. Source fingerprint includes
all tracked/new Go and proto files plus go.mod/go.sum: 1179 paths, SHA256
`fbe8d752d959c11c250c0240aeb33ca31d4735eefeb6ae6c63a078b0bf8f6ce3`.
The unchanged original behavior fixture SHA256 remains
`f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.

| Check | Result |
| --- | --- |
| Full affected race suite, including new runtime/reference cases | PASS; core 288.857s, conf 11.349s, serial 9.480s, mKCP 69.533s, HTTP2 19.867s, QUIC 41.230s; remaining affected packages pass |
| Original behavior fixture | PASS on pinned original (7.585s) and within the fork's full conf suite; identical fixture hash |
| Seventeen retained original scenarios, race enabled | PASS, 334.065s |
| Whole-tree test compilation | PASS, `go test ./... -run '^$' -count=1 -timeout=120s`; compile-only |
| Whole-tree vet | PASS, `go vet ./...`, exit 0 |
| Same-source private CLI builds | PASS Windows/amd64, Linux/amd64, Darwin/amd64 and Darwin/arm64; CGO=0, trimpath, stripped |
| Windows CLI | PASS six direct fixtures, six exit-23 rejections, two explicit directory imports and merged-payload checks |
| Excluded proxy dependency audit | PASS; no SSH/Hysteria/WireGuard/MASQUE/TUIC/AnyTLS/ShadowTLS proxy dependency |

Packages with no test files represent compilation, not an additional runtime
test. The CLI dump checker accounts for the original warning diagnostics that
precede its JSON payload; that existing diagnostic behavior is unchanged.
An earlier scenario run was superseded when the multi-file regression was fixed;
it was stopped and its owned test servers closed. It is not counted as a pass.
The final affected/scenario runs above completed on the final source fingerprint.

Private validation builds (not distribution artifacts):

| Target | Bytes | SHA256 |
| --- | ---: | --- |
| Windows/amd64 | 34136576 | `85849eec462bce5baace73ee5c094f51944a57b4fd7476621a9779ae3bf15807` |
| Linux/amd64 | 33697952 | `d5d427b7282f01c9a2850cf4a3d5d2e99e3ccd3f018bb9bb1700962bfd7bdfd6` |
| Darwin/amd64 | 34300320 | `5a22c4350dc2582590d2b62ab48b5a0cb9f2510008922534118118762f7f322c` |
| Darwin/arm64 | 32223954 | `8b874eb1f719d7c820461de8bc6b4d2be3a389f202888fb9991ce1a39c031bed` |

The Windows build is 73728 bytes (0.22%) larger than the previous documented
four-protocol build with equivalent Go/CGO/trimpath/stripping settings. Its VCS
stamp is `ea89e85-dirty`: the tested candidate parent plus these reviewed edits,
not a claim that the private executable was built from a later clean commit.
Evidence logs, executables and generated fixtures stay outside Git.

## Acceptance limits

These are local synthetic Windows runtime/wire/race checks and foreign CLI
cross-builds. They do not establish Internet/private-server compatibility,
Linux/macOS runtime, packaging, mobile/native ABI, TUN privileges or full SDK
integration. No speed or memory improvement is claimed.

Default/multiplexed SIP003 framing, external plugin executables, simple-obfs,
plugin QUIC modes, QUIC browser TLS fingerprints and filesystem-bearing XDrive
node links remain unsupported. Full original configurations within the retained
scope keep their original builders and semantics. Existing external TLS ECH
failure evidence is not relabeled green; offline affected checks are not a
whole-tree runtime pass. Main, releases, README, workflows and owner compatibility
runners remain untouched, with no workflow dispatch or monitoring.
