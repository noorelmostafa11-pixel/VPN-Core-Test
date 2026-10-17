# Preserve original behavior; isolate added support

Selection update: normal node-URI input now generates the matching internal
configuration automatically, with no manual feature switches. Original JSON
semantics below are still preserved; its low-level legacy fields are not a
requirement in node links. See [automatic node selection](VERIFICATION-NODE-SELECTION.md).

Date: 2026-10-17. Source parent: `cf7b0bc3ba8f15bbad6c104bca33c82303670bba`.
Comparison authority for original Xray behavior:
`701af60772cda123492f86e383e1fdba066614a9`, the pinned upstream foundation.
This is a correction of integration boundaries, not a new protocol batch.

## Selection contract

Working original configurations require no edits. Do not reinterpret an old
ignored field, retry a failed modern connection with weaker crypto, or change a
shared default to enable an addition. An ambiguous node needs separate explicit
metadata: the same original JSON cannot simultaneously mean two wire protocols.
There is no claim of automatic server-type detection or completed SDK importing.

| Area | Original/default behavior | Separate additional path |
| --- | --- | --- |
| VMess alterId | Top-level flat/user alterId stays ignored, including unrelated JSON types | `legacySettings.alterId` selects bounded historical headers |
| VMess security | Original GCM/ChaCha/AUTO behavior; CFB/none/zero/unknown names still fall back to AUTO | `legacySettings.security` selects the added body; unknown values in this block reject |
| VMess inbound | Modern headers and authenticated bodies remain the default | Per-user `legacySettings`; weak bodies additionally need its `allowLegacyBody: true` |
| SOCKS | Original `socks` remains SOCKS5, ignoring top-level version; original port acceptance remains | New `socks4`/`socks4a` selector, or `legacySettings.version` |
| SOCKS Go handshake API | `ClientHandshake` is restored byte-for-byte to the pinned source | Selected SOCKS4 client explicitly calls its separate handshake |
| HTTP2 | Inactive httpSettings cannot reject or alter TCP/XHTTP/WebSocket/gRPC configuration | Only selected http/h2/http2/h2c parses and builds those settings, honoring method overrides |
| Shadowsocks accounts | Original-method pairs keep original key-based equality | Comparisons involving an added method also distinguish cipher type |
| Shadowsocks initial payload | Original methods keep the original default empty-payload behavior | `serverFirstCompatibility: true` enables the fix; added methods use their added path |

Modern VMess protobuf accounts also ignore alter_id/allow_legacy_body unless
the new `legacy_compatibility` gate is true. SOCKS protobuf accounts require
that gate to select version4/4a; otherwise they remain SOCKS5. Original field
numbers and module/dependencies are unchanged; the gates are new fields.

## Synthetic examples and migration

These are settings fragments, not private nodes or a replacement for working
original profiles. Flat VMess settings and vnext users use the same block:

```json
{
  "id": "00000000-0000-4000-8000-000000000001",
  "legacySettings": { "alterId": 16, "security": "aes-128-cfb" }
}
```

An inbound user intentionally accepting this weak body needs:

```json
{
  "id": "00000000-0000-4000-8000-000000000001",
  "legacySettings": { "alterId": 16, "allowLegacyBody": true }
}
```

For an existing `socks` selector, added settings are
`"legacySettings": {"version":"4a"}`; the unambiguous new `socks4a` protocol
selector needs no block. Password/IPv6/UDP restrictions apply only to that
selected legacy client, not the original SOCKS5 path.

For original Shadowsocks methods, `"serverFirstCompatibility": true` in client
settings opts into suppressing the empty initial end marker. This changes a
previously broken server-first case, but is no longer a hidden default change.
An added method such as aes-192-gcm already selects the additional path.

Configurations written for earlier fork checkpoints to activate VMess legacy
semantics must move the added fields into legacySettings; earlier SOCKS version
selection must use that block or a new protocol selector. Do not rewrite
existing upstream profiles. Tests deliberately targeting the optional original-
method Shadowsocks fix must select it explicitly; owner-managed compatibility
runners were not inspected, changed or run in this correction.

## Audit boundaries

The shared production edits since pinned upstream were reviewed, distinguishing
added selectors/codecs and integration hooks from behavior changes. Added
Shadowsocks cipher names have no collision with accepted upstream names; the
AEAD-only multi-user restriction is retained. Original key lengths16/32, TCP
prelude50, framing and UDP format are unchanged. Ciphers with new names use
their added key/IV/framing paths. Existing modern VMess framing/padding, replay
handling and AEAD-first validation remain in place; legacy lookup is separate.

The owner's TLS certificate reload synchronization, VLESS unsafe-pointer race
fixes, XHTTP protobuf-lock fix, outbound tag locks, routing-stat delivery and
test fixes are preserved. They are not reverted to the raw upstream foundation.
The unreachable reverse/VMess-command cleanup still returns the same errors.

Malformed Shadowsocks buffer bounds checks are retained rather than restoring
out-of-range slicing/panics. Original valid packets do not use a new wire
format. This is not a promise of identical error strings or crashes for invalid
frames, nor a claim that source files are byte-identical to upstream.

## Verification

The exact same `infra/conf/original_behavior_test.go` is run against a clean
export of pinned upstream and the fork. Expectations use only original APIs:
flat/nested/inbound VMess, ignored alterId values, security fallback with
AuthenticatedLength, SOCKS5 configuration and handshake bytes, inactive HTTP2
settings on five original transports, and original Shadowsocks account equality.
It first failed on the uncorrected fork while passing on upstream. After
isolation it passes on both. Final shared fixture SHA256:
`f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.

Focused new-and-original race checks passed for conf, Shadowsocks, VMess,
encoding/outbound, SOCKS and standalone HTTP2. VMess's live loopback test now
checks both selections for each of five body names and alterId0/16/64: 30 cases
with server-first then exact120003-byte fragmented TCP echoes. The original
selection uses a modern-only account, proving an ignored alterId cannot trigger
the legacy header. Independent legacy wire oracles and malformed/replay checks
are retained, not replaced by this matrix.

Shadowsocks live loopback checks cover four original AEAD methods plus added
AES192-GCM/CFB, both original data-first and explicitly selected server-first:
12 cases with exact120003-byte fragmented TCP echoes. Empty initial buffers are
also checked directly with and without the option. SOCKS independent-wire and
HTTP2 independent-peer tests remain. These peers are local synthetic fixtures;
they are not external private-node or Internet acceptance.

Final local results, Go1.27.1 Windows/amd64 with GCC16.2 race support:

| Check | Result |
| --- | --- |
| Final identical shared fixture on clean upstream export | PASS race6.234s |
| Full final conf/SOCKS packages, including original fixture | PASS race11.522s/9.731s |
| Full Shadowsocks/SS2022/VMess account packages | PASS race13.056s/5.622s/5.740s |
| Full VMess AEAD/encoding/outbound packages | PASS race196.252s/19.622s/2.231s; inbound compiles, no test files |
| Full standalone HTTP2/core packages | PASS race7.670s/186.542s |
| 20 selected original runtime scenarios | PASS race175.694s |
| Vet: affected packages, core and distro registration | PASS exit0 |
| Same-source Windows CLI build and version execution | PASS exit0; no distribution job |

The original scenarios cover four Shadowsocks TCP/UDP/Mux cases, five SOCKS5
TCP/HTTP/UDP/routing/conformance cases, four VLESS plain/TLS/Vision/REALITY cases
and seven modern VMess TCP/UDP/Mux/AuthenticatedLength/NoTerminationSignal cases.
No KCP or external fingerprint/ECH scenario was selected. The interrupted first
broad command is not counted as a completed pass: its completed package results
were retained, remaining packages were completed separately, and final SOCKS/conf
were rerun after their last production edit. This is a union of completed
affected-package checks, not a successful single whole-tree command.

Local binary outside Git: `xray-fork-preservation-20261017.exe`,35191296 bytes,
SHA256 `1ca6c61f77d1a286e4ec9b1deb55e71485d6dfa311c253d40022ffbfa1eb9b5d`.
Version reports `cf7b0bc-dirty`, correctly identifying parent plus local edits,
not a future clean commit. No protocol was removed for size. Raw protoc33.5 /
protoc-gen-go1.36.11 regeneration is identical for all three changed schemas.

Evidence outside Git in the private report-review directory:
`xray-isolation-before.log`, `xray-isolation-original-complete-race.log`,
`xray-isolation-focused-race.log`, `xray-isolation-final-socks-conf.log`,
`xray-isolation-affected-race.log` (interrupted),
`xray-isolation-remaining-race.log`/exit marker,
`xray-isolation-original-scenarios-resumed.log`/exit marker,
`xray-isolation-build.log` and `xray-isolation-vet.log` (empty successful vet).

The local test-only compilation error from initially naming a nonexistent
context helper is retained in the evidence; it was corrected using the existing
test context key, without assertion/deadline changes. No protocol retry-until-
green or test weakening was used.

## Publication recheck

At the owner's explicit publication request, the unchanged shared fixture passed
again on clean upstream (race7.922s). Original-plus-added focused race checks
passed again on conf9.615s, Shadowsocks10.300s, SOCKS5.782s, VMess4.659s,
encoding13.682s, outbound2.665s and HTTP2 7.437s. No assertions were changed.
Rebuilding current source produced the exact same binary SHA256 recorded above.
All1182 Go/protobuf/module source files remained unchanged during these checks;
the SHA256 of sorted Git-blob-ID/path lines is
`04382360550419f53ba23762cfcd4b8e3604e75de51bebffb1846e5e8ac4aadc`.
Owner stability paths, workflows/check/wire, README, dependencies and license
were checked unchanged from the source parent. Publication is scoped to the
feature branch only, with no CI dispatch, PR, package or release action.

The known unchanged external TLS TestECHDial failure is not fixed or relabeled
green. No whole-repository/CI, foreign-platform runtime, Internet, mobile/package,
SDK, maximum-size UDP or complete compatibility claim is made. No workflows,
fork/check, fork/wire, main, releases, owner's README or private material changed.
