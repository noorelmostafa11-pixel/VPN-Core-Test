# Legacy QUIC historical protobuf packet headers

Date: 2026-10-17. Development parent: `76a1cf5c93b956600e3bd08d4fece0a51411adcc`.
Resumed and integrated on `6c707eb2f28a398a2c0d4444b5e44f345bf00577`, preserving
its owner test fixes. Current combined-source results accompany
[the in-path selection record](VERIFICATION-IN-PATH-ADDONS.md).
This extends the separate legacy QUIC carrier. It does not modify original
Xray transports, security defaults, packet encryption, JSON/URI selection,
modern QUIC parameters, dependencies or the owner's stability fixes.

## Input and provenance

Historical QUIC `Config.header` field3 now accepts its seven original protobuf
message names under `xray.transport.internet.headers`:

| Message suffix | Packet camouflage |
| --- | --- |
| `noop.Config` | None |
| `srtp.Config` | SRTP |
| `utp.Config` | uTP |
| `tls.PacketConfig` | DTLS |
| `wechat.VideoConfig` | WeChat |
| `wireguard.WireguardConfig` | WireGuard |
| `dns.Config` | DNS, including its domain |

The six restored schemas are byte-identical Git blobs to pre-removal Xray
`ab3c00e96b3af6885c09acfdd1f8d36e60d90bad`; noop already exists unchanged.
Names, field numbers and options are retained. Their Go outputs use raw
protoc33.5/protoc-gen-go1.36.11, with identical regeneration. No removed generic
packet-header runtime/API or old transport implementation is restored wholesale.
QUIC's own existing config.proto/config.pb.go are unchanged (field3 was reserved
for this historical meaning, not reused for a new selector).

Historical SRTP/uTP constructors ignored their configuration fields. Non-default
version/flag/payload values therefore remain ignored instead of gaining a new
wire meaning. Historical DNS domain packing is isolated from the existing named
JSON/URI header path: root/empty, trailing dots, escaped characters and duplicate
singular protobuf fields retain the old packing/last-value behavior. DNS IDs
and other packet counters use the existing QUIC packet writer.

Selection is automatic from the supplied protobuf type, without an enable flag.
Original JSON/URI selectors still use fields4/5 and their unchanged defaults and
validation. Combining the two representations is rejected, not silently resolved
by precedence. Only the seven packet message names are decoded; arbitrary
security/transport TypedMessages and look-alike names are not instantiated.
Unknown structurally valid fields remain ignored, without mutating the input.

## Bounds and safety

Typed header payloads are limited to4096 bytes and unknown protobuf groups to16
nested levels. An iterative wire scan enforces the latter because protobuf's
message RecursionLimit does not constrain unknown groups. Truncated/malformed
wire data, invalid UTF-8 DNS strings, unsupported types and conflicting selectors
are rejected with sanitized errors. Historical encoded DNS names fit the old
256-byte buffer including their terminal zero; the old buf[:257] panic boundary
is rejected before slicing. These are bounds on the newly accepted path, not
changes to existing transport defaults or an authentication-policy fallback.

Camouflage is not real SRTP/DTLS/WireGuard/DNS and is not authentication. Existing
outer packet AEAD, QUIC TLS/pins, fingerprint rejection and no-TLS-settings
internal-certificate semantics are unchanged. No data is replayed as a probe.

## Checks completed before the interrupted conversation

Go1.27.1, Windows/amd64, GCC16.2 for race detection. Source1220 Go/protobuf/module
paths fingerprint:
`b7f05950b1832934fbab1a8d7e570b661be6bb57f24070e62f9096d54e9f6173`.
This fingerprint describes the pending typed-header batch before the later
owner test fixes and unified node-description integration. It is not the
current combined-source fingerprint; see the integration record above.

- Literal historical protobuf payloads and packet golden bytes cover all seven
  message types, including non-default ignored SRTP/uTP fields. Roundtrips and
  concurrent validation prove the supplied config is not rewritten.
-42 independent endpoint cases cover seven message types x3 packet ciphers x2
  roles, with pinned TLS, an actual opening application byte, a server greeting,
  exact fragmented120003-byte upload/download and half-close. Independent peers
  use literal prefixes and the separately checked packet KDF, not the new typed
  converter/header serializer. Existing48 named-header endpoint cases remain.
- A full VLESS core case enters through ordinary protobuf loading on both sides,
  including nested receiver/sender TypedMessages, server-first target data and
  exact120003-byte echo. Existing JSON/URI core cases remain unchanged.
- New typed/core cases repeated five times with race detection PASS43.446s.
- The unchanged shared original-behavior fixture on pinned upstream PASS
  race7.330s; its SHA256 remains
  `f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.
- Vet of affected config/serial/main/core, QUIC, HTTP2, internet, XHTTP, Hysteria
  and all header packages PASS,exit0,no diagnostics.
- Same-source stripped CGO0 CLI builds PASS Windows/amd64, Linux/amd64 and
  Darwin/arm64. Foreign compilation is not foreign runtime acceptance. The
  Windows CLI passes version and ordinary synthetic `.uri` configuration
  checks. Binary outside Git: `xray-fork-quic-typed-20261017.exe`,35369984 bytes,
  SHA256 `9a933efd18273e61378827b74653c6b0c7856d5f39d9e799a93a9beab6805d67`.
  Version `76a1cf5-dirty` identifies the tested source before its commit, not a
  clean future revision. No size-reduction claim or distributable publication.

Those previously running checks subsequently completed: full affected race
PASS (conf9.529s,core177.357s,QUIC16.999s,HTTP2 17.851s and the other selected
packages),20 original scenarios PASS197.935s, fixed-budget fuzz PASS20000
executions16.196s. These logs were recovered at resume. Final current-source
checks are separately recorded in the integration record before publication.

Retained findings: the before-test rejects all seven historical messages. The
first extended validation exposed the unknown-group depth gap; the iterative
bound was added, retaining the rejection assertion. Its empty-DNS golden was
also corrected to the actual historical two-zero encoding, not by changing
production packing. A short timed fuzz run finished with0/8 seed cases completed
and is not counted as fuzz evidence; a fixed execution budget replaces it.
No existing assertion, deadline, TLS rule or original runtime path was weakened.

Evidence is outside Git with `xray-quic-typed-` prefixes: before, goldens,
validation, first-runtime, bounded-runtime, core, final-affected, final-repeated,
original-baseline, final-scenarios, final-vet, final-fuzz, final-fuzz-20000x,
final-build/final-cli and crossbuild-linux/darwin. No private node/profile/key
material is used. No workflow/check/wire runner is changed, run or monitored.

## Remaining limits

Explicit browser/uTLS fingerprints, custom modern QUIC tuning and unsupported
packet carriers remain rejected. This is not full historical SDK/application
ABI restoration, proxy-level UDP, main executable wire, private-node, Internet,
mobile or foreign OS runtime acceptance. The known external ECH failure is
unchanged, not rerun or relabeled green. Main, releases and owner files remain
untouched; compatibility remains under the owner's control.
