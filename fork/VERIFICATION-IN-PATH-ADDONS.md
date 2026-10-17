# One Xray lifecycle with in-path capability selection

Date: 2026-10-17. Parent: `6c707eb2f28a398a2c0d4444b5e44f345bf00577`.
This implements a shared connection-data integration point. It is not another
core, a fallback process, a runtime protocol probe or an application rewrite.
The parent's four test/evidence corrections are retained, including the QUIC
UDP port selection and the HTTP2/REALITY race corrections.

## Integration and original behavior

`infra/conf/node_selection.go:ResolveNode` owns node capability decisions.
URI syntax is read by `DescribeNodeURI`; versioned node JSON is read by
`DecodeNodeDescription`; Go callers supply the same `NodeDescription`.
Each reaches `ResolveNode`, which validates connection data, selects required
implemented additions, generates their internal representations, and validates
the existing Xray outbound/stream configuration. The ordinary configuration
loader, handler registration, routing, dialing and core lifecycle then run it.

The transport helper constructs transport settings, and the original components
validate their own TLS/REALITY/protocol contracts. Neither helper chooses a
second engine. The returned `NodeSelection.Addons` is an inspectable decision
report, not an activation API, mutable global registry or retry list. Selection
does not open a connection, replay bytes or interpret a network/auth error.

Original full Xray JSON and protobuf never enter this node-description resolver.
Their ignored fields, AUTO defaults, low-level selectors and working original
paths keep their established interpretation. The only shared loader changes
register a new `node` input syntax/extension and merger decoder; existing input
branches and default configuration-directory discovery remain unchanged.
No original protocol, TLS/REALITY implementation, routing implementation,
dependency, workflow, compatibility runner or shared original fixture is edited.

## Implemented capability inventory

This inventory includes the later Hysteria2 input adapter and SSH forwarding
batches. Their linked records contain their own validation; the verification
section below retains the original refactor checkpoint's results.

| Connection data | Selected responsibility | Core representation and limit |
| --- | --- | --- |
| Modern VLESS/VMess, Trojan, SOCKS5, HTTP/HTTPS; original transports | Original registered support | No legacy selector for a base node; original authentication and security validation |
| Hysteria2 protocol metadata | Original registered support | Existing Hysteria2 handler/transport, TLS, pins and Salamander; [input adapter scope](VERIFICATION-NODE-HYSTERIA2.md) |
| VMess alterId1..64 | `vmess-legacy-header` | Matching internal legacy account fields; bounded historical header/replay implementation |
| VMess CFB/NONE/ZERO body | `vmess-legacy-body` | Explicit internal body selector; ZERO remains raw TCP-only semantics |
| Added classic SS method | `shadowsocks-added-cipher` | Matching method enum/key/IV; unauthenticated methods remain single-user |
| Classic SS node input | `shadowsocks-server-first` | Preserves the existing URI importer's empty-initial-payload contract; never changes original full JSON defaults |
| SOCKS4/4a protocol | `socks4` | Existing registered SOCKS4 CONNECT implementation; no password/UDP/IPv6 substitution |
| HTTP/H2/H2C transport | `standalone-http2` | Existing separate HTTP2 carrier, with its TLS/REALITY/h2c rules |
| QUIC transport | `standalone-quic` | Existing separate legacy QUIC carrier; browser fingerprints/unsupported tuning still reject |
| SSH protocol, username/password and verified host pin | `ssh-tcp-forwarding` | Added registered TCP forwarding handler with existing Xray lifecycle/routing; [SSH bounds and checks](VERIFICATION-SSH.md) |

SS2022 stays in the original SS2022 handler, without the unrelated classic
server-first selector. Classic SS server-first behavior is a retained node-input
contract from the previous published reader, not a newly inferred network-peer
property. An original-method full Xray config still has its original default.

Metadata can select more than one responsibility (for example legacy VMess body
and header over QUIC). Unknown ciphers, protocols, transports, conflicting
aliases and unsupported security pairings reject; capabilities are never tried
in sequence. The supported vocabulary stays bounded to the already implemented
common node imports. Missing Hysteria1/TUIC/AnyTLS/ShadowTLS and remaining
subscription/plugin variants remain unsupported. SSH is a subsequent added
handler, not an implicit protocol alias created by the original refactor.

The resumed pending QUIC adapter also restores the seven historical typed packet
headers within the already registered QUIC transport. Its independent wire
checks and bounds are recorded in [the separate record](VERIFICATION-QUIC-TYPED-HEADERS.md).

## Input contract and entry points

One node description has version1, a protocol/address/nonzero port, optional
name, protocol-specific credentials and connection `parameters`. Parameters
are strings with the same meaning and alias/conflict rules as URI query data.
Credentials use `id` for VMess/VLESS, `method` plus `password` for SS, `password`
for Trojan/Hysteria2, `username`/optional `password` for SOCKS/HTTP, or required
`username`/`password` plus a host-key parameter for SSH. Mixed credential
types reject. This JSON object is never auto-detected inside an original `.json`.

Synthetic example, using metadata instead of a manual legacy enable switch:

```json
{
  "version": 1,
  "protocol": "vmess",
  "address": "127.0.0.1",
  "port": 443,
  "credentials": {"id": "00000000-0000-4000-8000-000000000001"},
  "parameters": {"cipher": "aes-128-cfb", "aid": "16", "type": "tcp"}
}
```

- CLI: `xray run -c synthetic.node`, using ordinary format detection. Explicit
  `.node` files join the existing merger/dump path; default directory discovery
  is unchanged. `.uri` input continues to work without changes.
- Standard distro Go reader: `core.StartInstance("node", data)` or the existing
  `core.StartInstance("uri", data)`; both use the same core.
- Typed Go integration: `conf.ResolveNode(description)`, then its outbound enters
  the ordinary `conf.Config.Build`/core lifecycle. `Addons` reports the selection.
- Conversion: `conf.ParseNodeJSON(data)` and the existing `conf.ParseNodeURI`.

Limits:64KiB input/description,64 parameters,256-byte labels, bounded existing
codec settings. Direct Go input is bounded before serialization. JSON requires
the declared version and types; duplicate keys (including case aliases), unknown
fields, mixed credentials and trailing objects reject. Unknown metadata cannot
inject arbitrary handler settings, certificate paths or local key files.
Errors omit original credentials and do not wrap secret-bearing builder errors.
Descriptions and their maps/passwords are not rewritten or retained globally.

## Verification

The before-test failed because normal distro format `node` was unregistered;
`xray-in-path-before.log` retains the result. After integration, the new format,
ordinary file detection/merging and unchanged directory discovery pass.

The focused race suite passes across config/serial/main/core, SS, SOCKS, VMess
encoding, HTTP2 and QUIC. Tests compare URI, independent structured descriptions
and direct Go selection at the generated protobuf boundary. Base nodes select
no addition and match ordinary original configuration. Additional cases cover
each implemented capability, TLS/REALITY metadata, malformed/ambiguous input,
version/size limits and concurrent read-only use of one shared description.

Live tests retain their original JSON/URI cases and add `.node` cases:60 VMess
header/body selections,36 classic SS data-first/server-first cases,12 independent
SOCKS4/4a cases,9 HTTP2/h2c/REALITY core cases, and4 QUIC core cases (including
historical protobuf). They require exact application bytes, server-first data,
fragmentation and owned peer cleanup; configuration parsing alone is insufficient.

Final source:1228 Go/protobuf/module paths, fingerprint
`fe5dd7c148313714e680f39471f60ff62e39decba6554388d52b06f7efd3d63c`.
Only documentation changes after these checks; the fingerprint is rechecked
before publication.

| Final-source check | Result |
| --- | --- |
| Full affected race suite | PASS: conf18.586s,serial12.285s,common/serial5.245s,main17.710s,core303.807s,SS24.887s,SS2022 7.645s,SOCKS13.755s,VMess7.058s,AEAD269.613s,encoding42.861s,outbound3.418s,QUIC34.934s,HTTP2 19.299s,internet4.855s,XHTTP9.259s,Hysteria10.513s,headers/http3.873s |
| Shared original fixture on pinned upstream | PASS race12.009s; expectations unchanged; all1123 baseline Go/protobuf/module files match pinned Git source after checkout CRLF normalization |
|20 unchanged original scenarios | PASS race346.628s; same bounded360s suite, no retry or deadline change |
| Description fuzz | PASS20000 executions,2 workers,39.800s total |
| URI fuzz | PASS20028 executions,2 workers,37.046s total |
| Typed QUIC header fuzz | PASS20000 executions,2 workers,20.010s total |
| Vet | PASS exit0, no diagnostics, all affected packages and the new reader |
| CLI compilation | PASS Windows/amd64,Linux/amd64,Darwin/arm64; CGO0,trimpath,stripped |
| Windows CLI execution | PASS version and ordinary `.node`/`.uri` configuration checks |
| Historical protobufs | Six schemas match their pinned pre-removal Git blobs; six generated outputs regenerate identically |

VMess inbound and the six restored schema-only packages have no test files;
their entries represent compilation, not separate runtime test claims. The
existing transport tests exercise the schema outputs through actual QUIC peers.

Edited code passes whitespace checks. The restored DNS schema intentionally
retains its pinned upstream trailing blank line; only that file is exempt from
the blank-at-EOF style rule, and its complete Git blob still matches upstream.

The shared fixture SHA256 stays
`f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.
Windows CLI outside Git: `xray-fork-in-path-20261017.exe`,35382272 bytes,SHA256
`744c1dae5e7652089076ac65a4851cb0442c4200a9af702b37ecca300b331262`.
Its `6c707eb-dirty` version names the tested parent plus final changes, not a
future clean commit. No binary is published and no size reduction is claimed.

Evidence is retained outside Git under `xray-in-path-`: before, first/expanded
focused checks, final-source snapshot, full affected race/scenario/vet exit
markers, both upstream runs, three fixed-budget fuzz logs, builds and CLI checks.
The first upstream byte comparison exposed checkout CRLF conversion rather
than a source-code difference; the complete normalized comparison verifies all
1123 source/module paths. The restored shared fixture remains byte-identical.

## Acceptance boundary

Runtime checks here use Windows/amd64 with Go1.27.1 and GCC16.2. Foreign builds
are compilation only. The unchanged original-behavior fixture must pass both
the fork and pinned upstream without changing its expectations. A green local
suite is not Internet/private-node acceptance, all-platform runtime, APK/SDK
linkage or complete application ABI compatibility. Original protobuf meaning
is protected, not automatically upgraded to a new node-description schema.
The existing external ECH failure is not fixed or relabeled green. No workflow
is dispatched/monitored; main/releases/owner README/private material are preserved.
