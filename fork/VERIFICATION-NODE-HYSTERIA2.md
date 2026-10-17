# Hysteria2 in the shared node-input path

Date: 2026-10-17. Parent: `3fa1b31e50a1250f57255c9f6d0e8c110f7184e0`.
This closes an input gap in the shared connection-data resolver. Xray already
implements Hysteria2; this batch does not port or modify its wire, authentication,
TLS, congestion, UDP, obfuscation or connection-manager implementations.

## Mapping and original behavior

The existing URI syntax reader now recognizes `hy2` and `hysteria2`, supplies
port443 when omitted and preserves percent-encoded opaque auth or user:password
auth bytes. `ResolveNode` accepts the same protocol names and password credential
in version1 node descriptions. It supplies original `hysteria` handler/transport
settings, with internal version2 and the exact supplied auth. No manual support
switch or alternate core is needed. `NodeSelection.Addons` stays empty because
the selected protocol is original upstream support.

The [official URI contract](https://v2.hysteria.network/docs/developers/URI-Scheme/)
defines the two names, optional port, userpass envelope, SNI, certificate pin and
obfuscation metadata. The input adapter accepts a bounded subset of that
contract; it does not claim every optional variant or complete main URI parity.
The pinned comparison main's Hysteria parser also requires explicit nonempty
auth and defaults to443. The ambiguous `hysteria` URI scheme is not reinterpreted
as version2; Hysteria1 remains separate pending work.

| Node data | Existing configuration selected |
| --- | --- |
| `hy2`/`hysteria2` plus password credential | Protocol `hysteria`, settings version2, transport `hysteria`, auth in its original transport config |
| No transport/security override | Original Hysteria2 carrier and required TLS, ALPN h3 |
| SNI/ECH metadata | Existing TLS settings/validation; no custom handshake implementation |
| `pinSHA256` or matching `pcs` alias | Canonical SHA256 certificate hash in existing TLS pin settings; invalid/conflicting pins reject |
| `obfs=salamander` plus password | Existing Salamander UDP final-mask settings; minimum4-byte, maximum4096-byte password |

Full original Xray JSON/protobuf, handlers, transports, security policies,
defaults and application paths are unchanged. Ordinary unpinned TLS still
requires trusted certificates. A valid explicit certificate pin uses the
existing TLS pin contract. `insecure=1` remains rejected by the original TLS
builder; there is no certificate-policy fallback after failure. Explicit TCP
browser fingerprints reject instead of being silently substituted with QUIC
ChromeParrot/native behavior. Existing QUIC defaults are retained when no such
fingerprint is supplied. Credentials are bounded, preserved and omitted from
import errors. Mixed credential types and malformed/contradictory metadata reject.

Supported input routes are the existing `.uri`, `.node` and typed Go description
entry points. Each uses `ResolveNode`, then the normal Xray configuration/core
lifecycle. No workflow, compatibility runner, dependency, protobuf, original
runtime component or private profile is edited by this batch.

## Rejected variants

The adapter currently rejects port hopping/multiple ports, realm-mode URIs,
Gecko import, bandwidth/congestion options and unknown transport metadata.
This is a limit of this bounded importer, not removal of existing full Xray
configuration capabilities. No Gecko default parameters are guessed. Missing
auth, mismatched protocol/transport, non-TLS security, unsupported ALPN and
orphan obfuscation passwords reject before any connection is opened.

## Verification

Before implementation, the new ordinary node-import test fails on the default
endpoint and unavailable scheme; `xray-node-hysteria2-before.log` retains this.
The initial config and live suites then pass. Tests compare equivalent URI,
structured JSON and direct Go descriptions at the built protobuf boundary.
Existing original-behavior expectations are unchanged.

The independent peer uses the pinned QUIC/HTTP3 library directly, literal
Hysteria2 TCP/UDP application framing and a separately written BLAKE2b Salamander
packet wrapper. It does not call Xray Hysteria handlers/transport/codecs or node
converters to generate its application wire. The protocol library itself is
shared; this is not an external Hysteria/main executable compatibility claim.

Ten live positive cases cover original full JSON, both URI names, structured
node JSON and direct Go input, each with and without Salamander. Each requires
one actual HTTP3 authentication, one TCP channel, a server-first greeting,
exact120003-byte fragmented TCP upload/download and separate UDP datagrams of
32/1400/3800 bytes, including fragmentation/reassembly and exact boundaries.
Six URI/node negative cases exercise wrong auth, wrong certificate pin and
untrusted self-signed certificates. They require actual network packets,
zero application channels/bytes and the expected authentication count, detecting
TLS bypass, protocol fallback or authentication retry. Owned peer workers join.

Final source:1231 Go/protobuf/module paths, fingerprint
`d9aeb6d12ae3d765b6212da9ee418af7ef3e5cd21f87a6dd283edeac57583ddb`.
Only documentation changes after these checks; the source snapshot is rechecked
before publication. Go1.27.1 Windows/amd64,GCC16.2 for race detection.

| Final-source check | Result |
| --- | --- |
| New config/live tests repeated5 with race | PASS conf10.231s,core18.366s |
| Full affected race packages | PASS conf9.587s,serial11.006s,main10.487s,core166.283s,Hysteria transport5.485s |
| Unchanged shared original fixture on pinned upstream | PASS race10.618s; also included in the fork's full conf run |
|20 unchanged original runtime scenarios | PASS race192.405s |
| URI fuzz including both new schemes | PASS20000 executions,2 workers,35.560s total |
| Structured-description fuzz including Hysteria2 | PASS20000 executions,2 workers,10.150s total |
| Vet | PASS affected packages/readers/distro registration,exit0,no diagnostics |
| Same-source CLI builds | PASS Windows/amd64,Linux/amd64,Darwin/arm64; CGO0,trimpath,stripped |
| Windows CLI checks | PASS version, ordinary `.uri` and `.node` configuration loading |

The original Hysteria proxy/account and Salamander packages have no local test
files; the full command compiles them and the live core peer cases exercise
their client-side implementations. No server-side parity claim is added.
The shared original fixture SHA256 stays
`f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.

CLI outside Git: `xray-fork-node-hysteria2-20261017.exe`,35388928 bytes,SHA256
`91c46061417e52c35495e7db40b3b0ec3fee6dddd8354abb301325d913fc6f16`.
Its version is `3fa1b31-dirty`, identifying the tested source before its commit,
not a future clean revision. The binary is not published, and no size reduction
or foreign-runtime acceptance is claimed. No protocol assertion or deadline was
weakened, and failed protocol attempts were not retried until green.

Only synthetic credentials/certificates and loopback peers are used. Evidence
remains outside Git with the `xray-node-hysteria2-` prefix. This is Windows
runtime/race evidence, not public/private-node Internet acceptance, foreign OS
runtime, application/SDK/Android linkage or complete URI compatibility. Main,
releases and owner files are preserved; compatibility dispatch remains with
the owner. The existing unrelated external ECH failure is not rerun or relabeled.
