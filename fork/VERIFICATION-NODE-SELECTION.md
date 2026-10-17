Historical checkpoint: the owner's 2026-10-17 four-protocol scope supersedes the protocol inventory below. See [current scope](VERIFICATION-FOUR-PROTOCOL-SCOPE.md) and [current resolver](VERIFICATION-IN-PATH-ADDONS.md). Removed remote protocols are not available.

# Automatic node selection without replacing original paths

Date: 2026-10-17. Parent: `a76d114b9695ecd2f3fe171cabcd3cfcd2d2c8dc`.
This implements the owner's clarified rule: additions expand acceptance alongside
the original implementation; users importing nodes must not enable features
individually. No protocol implementation is replaced by this batch.

## How selection works

All implemented handlers remain registered in the normal distribution. The new
URI reader identifies protocol, body cipher, transport and transport security
from the node itself, then constructs the matching existing configuration.
There is no enable-legacy switch in a node link, no probing traffic, no retry
with a weaker cipher, and no application payload replay to test candidates.

Supported node input in this batch:

- VMess base64 JSON share links and VMess userinfo/query links; aid0/16/64 and
  AUTO/GCM/ChaCha/CFB/NONE/ZERO choose their existing header/body paths.
- VLESS, Trojan, Shadowsocks, SOCKS5, SOCKS4/4a and HTTP/HTTPS proxy URLs.
- Existing raw/TCP, WebSocket, HTTPUpgrade, gRPC, XHTTP, HTTP2/h2c and default
  mKCP transport selections. TLS/REALITY metadata is preserved and validated by
  the original builders; an unsupported pairing remains an error, not another
  transport. HTTP2+REALITY is now available in the subsequent
  [pairing checkpoint](VERIFICATION-HTTP2-REALITY.md). Standalone QUIC now has a
  bounded [packet/TLS/stream implementation](VERIFICATION-LEGACY-QUIC.md).

For VMess, cipher and alterId come from the node profile; needed low-level
legacySettings/protobuf flags are generated internally. SOCKS4/4a selects the
registered matching client from the URI scheme. Shadowsocks node input includes
the added server-first handling automatically, including original AEAD methods.
No manually written legacySettings or serverFirstCompatibility is needed for
these node inputs. Those fields remain low-level/backward-compatible config
representations, not feature availability switches.

Original Xray JSON/protobuf preserves the behavior verified at the preservation
checkpoint. It cannot be silently reinterpreted as a different node schema:
the same ignored field cannot simultaneously mean both its old and new meaning.
The additional URI boundary removes that ambiguity using the source format and
the node's actual metadata. Malformed/contradictory/incomplete unsupported data
does not trigger guesses based on a failed connection.

## Entry points

- Standard CLI: `xray run -c node.uri`; its file extension selects the input
  reader automatically, without a feature flag. Existing config directory auto
  discovery is unchanged; explicit URI-only directory format is also supported.
- Go: `core.StartInstance("uri", []byte(nodeURI))` with the standard distro
  registration, just as JSON input requires its format registration.
- Conversion: `conf.ParseNodeURI(nodeURI)` returns a validated outbound DTO.
- Explicit URI files work in the existing multiple-file merger/dump path.

The format name/file extension selects input syntax, not which protocol features
are enabled. This is not the native core's complete application/mobile ABI or a
subscription importer; one bounded node is accepted per URI input file/reader.
No user profiles are rewritten or persisted by this reader.

## Validation and privacy

Input is bounded to64KiB,64 parameters, a256-byte label, nonzero valid endpoint
ports and bounded existing codec settings. Duplicate/conflicting metadata,
invalid UTF-8 credentials, unknown options and unsupported plugins fail with
sanitized errors rather than echoing links/passwords/keys. Plaintext fallback
and TLS certificate-verification bypass are never inferred from failure.
An explicit node certificate policy is preserved as data, not enabled by default.

XHTTP extra imports only an allowlist of transport/padding/mux fields. A remote
share link cannot inject certificate/key file paths, arbitrary nested download
stream settings or other local configuration. Original full JSON capabilities
remain unchanged. The reader does not perform network discovery or fetch keys.

This first import boundary does not yet reproduce every main URI alias,
subscription variant, TCP/KCP header variant, SIP003 plugin or advanced nested
XHTTP setting. Unknown data is reported, never silently discarded or translated
into a different wire protocol. Existing JSON support for other protocols is
not disabled by their URI importer being incomplete.

## Checks and acceptance boundary

The initial standard-core test failed because URI input was unregistered;
`xray-node-selection-before.log` preserves that failure. The URI reader is now
registered alongside the original readers. Existing original-behavior tests
remain unchanged, and protocol implementation files are unchanged.

New/expanded tests include:

- Both VMess share-link forms across6 body selectors and alterId0/16/64.
- All32 classic Shadowsocks names across userinfo/base64-user/base64-all forms,
  preserving passwords containing @, colon, percent, plus and slash.
- TLS/REALITY metadata, aliases/conflicts, private/public transport guards,
  duplicate JSON/query keys, reader limits, secret-safe errors and32 concurrent
  readers; bounded parser fuzzing is recorded separately.
-45 VMess live outbound cases: original JSON, added JSON and automatic URI
  selection, including server-first and exact120003-byte fragmented TCP echoes.
-24 Shadowsocks live cases: four original AEAD methods plus AES192-GCM/CFB,
  original JSON and automatic URI, both data-first and server-first.
-8 independent SOCKS4/4a wire peers across both JSON and URI entry points.
- VLESS over standalone h2c through an independent echo peer, both JSON and URI.
- Standard file-format auto detection, merging, bounds and unchanged original
  directory discovery.

Final source results (Go1.27.1 Windows/amd64; GCC16.2 race support):

| Check | Result |
| --- | --- |
| Focused original/new race suite | PASS conf12.442s,serial7.704s,main7.320s,core11.017s,SS14.180s,SOCKS9.692s,VMess encoding25.416s,HTTP2 7.735s |
| Full affected packages | PASS race conf11.592s,serial13.084s,main11.622s,core208.733s,SS19.273s,SOCKS12.832s,HTTP2 14.115s |
|20 unchanged original scenarios | PASS race193.747s; VLESS plain/TLS/Vision/REALITY, VMess modern modes, SS/SOCKS TCP/UDP/Mux/routing |
| Parser fuzzing | PASS13408 executions,2 workers,5s requested (6s reported,8.319s total), no failure |
| Vet | PASS affected packages,main/URI/core and encoding,exit0 |
| Same-source CLI build/version/config check | PASS; `.uri` detected with ordinary `-c` only; `Configuration OK` |

Original regression fixture SHA256 is unchanged:
`f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.
All1190 Go/protobuf/module source paths fingerprint:
`a7f1bb27dcb61cc034ab4301b280b1ac81de5807bf2e12820ce1a025bee072bc`.
CLI outside Git: `xray-fork-node-selection-20261017.exe`,35251712 bytes,
SHA256 `77ee24c8173efb5cb3689841ec9fa0efd055d29fae1623afa2c319abc06fd429`;
version `a76d114-dirty`, not a future clean commit. No size reduction is claimed.

Evidence: private `xray-node-selection-before`, `config`, `runtime-first`,
`focused-race`, `final-focused`, `affected-race`, `original-scenarios`, `fuzz`,
`build`, `vet` and `cli` logs; affected/scenario exit markers0. The intermediate
config run failed a negative test that used example.invalid, which the unchanged
upstream private-domain matcher treats as private. The fixture now uses a public
IP for the same plaintext-transport rejection assertion; original guards were
not altered. No assertions/deadlines or owner compatibility tests were weakened.

Publication recheck: all1190 source paths still match the fingerprint above.
The shared unchanged original-behavior fixture passed again on pinned upstream
with race detection (9.549s). The focused original/new race suite passed again
(conf10.718s,serial7.534s,main6.905s,core8.848s,SS12.316s,SOCKS9.308s,
VMess encoding19.378s,HTTP2 8.408s). Rebuilding the same source produced the
identical CLI SHA256 above, and the synthetic `.uri` config check passed again.
The prepublish-original, prepublish-race, prepublish-build and prepublish-cli
logs are retained outside Git. Only documentation changed after these checks.

This record accompanies the node-selection batch on `feature/xray-custom-core`.
This is synthetic Windows loopback/config/race evidence, not Internet/private-node acceptance,
foreign OS runtime, complete URI parity or application/mobile SDK acceptance.
The existing external ECH test failure is not fixed or relabeled green. No
workflow/check/wire runner, main, release, owner fix or private profile changed.
