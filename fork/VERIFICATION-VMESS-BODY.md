# VMess body modes with modern AEAD headers

Current configuration supersedes this historical checkpoint: VMess legacy
choices and inbound permissions now live inside `legacySettings`. Outside that
block, ignored alterId and AUTO fallbacks match pinned upstream. See
[preservation and migration](VERIFICATION-PRESERVATION.md).

Historical body-only checkpoint. Its alterId rejection notes describe that
revision, not current behavior. Explicit legacy headers were subsequently added
in [the next checkpoint](VERIFICATION-VMESS-LEGACY-HEADER.md); alterId0 and the
body-mode security policy below remain unchanged.

Date: 2026-10-16. Source base `6c349a025f2144bf22f04995261ab2cd0d0ebe72`
plus this patch. This restores three explicit body choices, not legacy VMess
header authentication. No workflow/check/wire runner or owner's fixes are changed.

| Config security | Wire code | Body behavior |
| --- | --- | --- |
| aes-128-cfb | 1 | Continuous AES-CFB over length, FNV checksum and data |
| none | 5 | Unencrypted length-framed stream or packet data |
| zero | 5 | Unencrypted, unframed TCP data; no chunk options |

CFB/NONE support the existing chunk masking and optional padding layouts.
ZERO is configuration-only, not security code6 on the wire. UDP and Mux with
ZERO are rejected instead of silently becoming another cipher; CFB/NONE support
framed UDP and Mux stream body codecs. An oversized legacy datagram is rejected
explicitly before writing any packet from that batch, not silently dropped.
With the current8192-byte buffer, safe payload limits are8186 bytes for CFB or
8190 for NONE without padding; padding reserves64 more bytes. This is not a
claim of main's maximum-size UDP packet compatibility.

FNV is an unkeyed checksum, not cryptographic authentication. NONE/ZERO provide
no body encryption or integrity. These are opt-in historical compatibility,
not recommended security settings. Modern AEAD defaults are unchanged. Request
and response headers still use the existing modern AEAD authentication and
replay checks; this addition does not claim forward secrecy for VMess.

## Settings and guards

Use an explicit VMess outbound `settings.security` of `aes-128-cfb`, `none` or
`zero`, with `alterId: 0`. Both flat settings and the existing vnext user form
retain the selected enum rather than substituting AUTO. Omitted security and
explicit auto keep the prior default. Unknown security names are now errors.

For a fork VMess inbound, each user that intentionally accepts these body modes
must specify `"allowLegacyBody": true` in that user's settings. It defaults to
false, survives the protobuf/memory roundtrip, and is enforced after identifying
the user. An ordinary inbound still rejects CFB/NONE, including raw ZERO-style
traffic. This does not remove or weaken header authentication for opted-in users.

AuthenticatedLength requires an AEAD body mode and is rejected for CFB/NONE/ZERO.
Nonzero alterId is rejected in JSON and protobuf inputs: timestamp/HMAC header
authentication and alter-ID key derivation remain a separate future port. Merely
ignoring this setting would connect with the wrong protocol. Existing protobuf
enum values remain unchanged; historical wire slots1/5 and configuration slot6
are restored. Account field2 records alterId for explicit rejection and field5
records the new inbound body-policy opt-in.

Packet layouts were reviewed against pinned main and historical upstream
[CFB/NONE encoding](https://raw.githubusercontent.com/XTLS/Xray-core/v1.4.5/proxy/vmess/encoding/client.go)
and [NONE framing](https://raw.githubusercontent.com/XTLS/Xray-core/v1.8.24/proxy/vmess/encoding/client.go).
Only the body behavior is restored; no native engine, module dependency or old
header validator is imported. Existing licenses and owner changes are retained.

## Local verification

- Before the patch all three explicit body names mapped to AUTO; the failing
  test evidence is retained. Configuration tests now check selectors, defaults,
  unknown names, inbound opt-in persistence, incompatible experiments and
  explicit rejection of nonzero alterId in both input forms.
- CFB/NONE codec matrix: TCP, UDP and Mux with plain, masked and padded lengths;
  large fragmented120003-byte streams; exact UDP packet boundaries and payloads
  of1/32/1400/3800 bytes; explicit end markers. ZERO is checked against raw bytes
  with no length/checksum fields. Independent standard-library FNV/AES-CFB wire
  construction checks the unmasked wire layout, not just a roundtrip.
- Malformed checks inject short checksums, corrupted/truncated CFB frames,
  lengths smaller than actual padding/checksum, invalid option combinations and
  oversized packet batches. Padding underflow is rejected before shared-reader
  slicing. Default versus explicit inbound acceptance and AEAD replay rejection
  are tested. No authentication or payload-equality assertion is weakened.
- Three real loopback TCP sessions run the full fork outbound against VMess
  codec peers, one per mode, receiving a greeting before sending application
  data, followed by exact120003-byte echoes and fragmented writes. They verify
  zero's actual header options and code5. These use the fork codec, not a claim
  of independent main/upstream executable interoperability.
- Focused tests passed ten race-enabled repetitions: vmess3.480s,
  encoding11.602s, outbound2.444s, infra/conf6.466s. Three network sessions per
  repetition also pass; UDP is codec-level coverage, not an Internet/node test.
  Final expanded flat/vnext configuration checks also pass count10 in3.750s.
- Full affected race suite passed: common/protocol2.848s, vmess2.206s,
  vmess/aead147.831s, encoding9.670s, outbound2.727s, infra/conf11.369s,
  core143.722s. Inbound has no standalone package tests. Vet passed protocol,
  all VMess packages and configuration.
- Existing GCM/ChaCha TCP, GCM UDP, Mux/MuxUDP and AuthenticatedLength/
  NoTerminationSignal scenarios passed with race enabled97.941s. No KCP scenario
  execution is claimed by that focused selection.
- Go1.27.1 Windows amd64, GCC16.2 for race. Protobuf regeneration is reproducible
  with protoc33.5/plugin1.36.11. Changed-source formatting/diff checks pass;
  module dependencies, root license, owner README and CI files are unchanged.

The initial new test fixture called a nonexistent validator.Close method and
failed compilation locally. The validator has no such lifecycle method; only
the owned session-history task needs closing. The fixture was corrected before
publication; initial logs are retained. Protocol checks and deadlines did not
change. No CI run/retry/monitor, release, Android or distributable package was
created. Local results do not establish foreign-OS runtime, Internet/private
nodes, full main parity, SDK/ABI or legacy alter-ID header acceptance.
