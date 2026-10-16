# Explicit legacy VMess alter-ID headers

Base: body checkpoint `e98b95fbb00d4b2577ba1711e3d2e40629b13c6c` plus this
patch. The prior JSON and protobuf guards rejected every positive alterId;
that missing behavior was confirmed in source before implementing this batch.

## Settings and safety boundaries

Both flat outbound settings and vnext users accept `alterId: 1..64`, explicitly
selecting the historical timestamp/HMAC request header. An inbound user with
positive alterId accepts those legacy IDs (and the primary ID), while continuing
to accept that user's modern AEAD requests. Zero or omitted alterId remains
modern-only: there is no negotiation, automatic downgrade or fallback after
modern AuthID replay, invalid-time or header-authentication failure.

The same body choices are available: `aes-128-gcm`, `chacha20-poly1305`, explicit
`aes-128-cfb`, `none` and TCP-only `zero`. AUTO still selects the modern body
algorithm. Legacy headers do not grant legacy-body permission: each inbound user
still needs `allowLegacyBody: true` for CFB/NONE/raw-NONE. ZERO is a configuration
selector, never wire security6. CFB/NONE reject AuthenticatedLength; AEAD bodies
retain that experiment, masking and padding.

Legacy header authentication and FNV checks are not modern AEAD protection or
forward secrecy. This restores an old, weaker protocol only for deliberate
compatibility use. No security improvement is claimed. Clock synchronization
within 120 seconds is required.

Limits are checked before account derivation or validator mutation:

- At most64 alter IDs per account; larger JSON/protobuf values fail explicitly.
- At most256 primary+derived identities across legacy-enabled users per inbound
  validator. Modern-only users do not consume this budget.
- Overlapping identities across users are rejected when either user enables
  legacy headers. Failed additions leave both user lists and budgets unchanged.
- A per-validator, on-demand10-second index includes at most66816 entries;
  timestamps are still checked against the current strict +/-120-second window.
  User add/remove invalidates the index. No new background task is introduced.
- A valid plaintext header is admitted only once per primary user/body key/IV
  for241 seconds, covering the full authentication horizon. The bounded8192
  session cache cleans expired entries at capacity and fails closed if still
  full; removal/re-addition does not erase replay history. Equal timestamp tokens
  alone are not replays: valid concurrent connections can share one token.

Body framing/UDP size limits remain those of the body checkpoint, not maximum
native UDP packet parity. Account equality keeps primary-user identity semantics.
No new module dependencies, implementation languages or fallback engine.

## Wire implementation and provenance

The wire design was checked against pinned main `b066df12`'s
`core/protocol.go` and `core/vmess_server.go`, plus historical upstream
[client](https://github.com/XTLS/Xray-core/blob/v1.4.5/proxy/vmess/encoding/client.go),
[server](https://github.com/XTLS/Xray-core/blob/v1.4.5/proxy/vmess/encoding/server.go)
and [ID derivation](https://github.com/XTLS/Xray-core/blob/v1.4.5/common/protocol/id.go).
The old global/timer-based validator was not imported.

Request auth uses HMAC-MD5 of the big-endian timestamp with a selected derived
ID; AES-CFB header encryption always uses the primary-ID command key and
MD5(timestamp repeated four times) IV. Response key and IV use MD5, not the
modern header mode's SHA256. CFB responses continue the exact cipher stream
after the four header bytes; AEAD/NONE bodies use their own established framing.
Header mode and both direction keys are frozen at session creation before the
outbound starts concurrent send/receive tasks.

Protobuf field2 keeps its wire number and now has implemented bounded semantics;
field5 body opt-in is unchanged. Only the field2 comment changes in generated
protobuf Go source; no schema layout changes.

## Local checks

Go1.27.1, Windows amd64; GCC16.2 for race detection. Results are recorded below
after validation of the final source. No compatibility workflow/check/wire
runner is modified, dispatched or followed.

New tests cover independent standard-library request/response byte oracles,
derived IDs1/16/64 and primary inbound ID, random client padding/checksum,
fragmented reads, every truncated request prefix, malformed version/reserved/
command/options/address/security/checksum, unchanged modern AuthID replay,
separate header/body policy, clock boundaries/epoch refresh, user removal,
identity budgets, replay expiry/capacity and concurrent valid connections.

The body matrix exercises both directions, CFB/NONE/GCM/ChaCha, TCP/UDP/Mux,
options1/5/13, plus authenticated lengths17/21/29 for AEAD bodies. Streams carry
120003 exact bytes; UDP preserves1/1400/3800-byte packet boundaries.
A separate independent CFB response oracle detects both IV resets and accidental
double encryption across the four-byte header boundary.

Real loopback tests run the full fork outbound against a fork-codec test peer:
five body selectors times alterId0/16/64, server-first greeting followed by a
120003-byte exact fragmented TCP echo. This is not an external server/main
interoperability test or Internet acceptance.

Initial failures were retained outside Git: a missing source brace stopped
local compilation; the first expanded runtime test then detected header-mode
and response-key initialization racing with the response task, causing incorrect
server-first handling. Initialization was moved to session creation, before
either task starts. No assertions, deadlines or protocol checks were weakened.

Final results:

- New/affected fork tests, race, count10: VMess6.996s, encoding76.866s,
  outbound1.967s, configuration4.095s. All15 real-loopback cases run each time.
- Added maximum-index/collision/modern-negative guards, race, count10:
  VMess20.770s, encoding13.078s. Final independent request oracle, race,
  count10:9.467s; its checksum comparison copies the expected plaintext to avoid
  overwriting the actual checksum during construction of the expected bytes.
- Full affected packages, race, count1: protocol5.600s, VMess4.662s,
  AEAD106.719s, encoding14.047s, outbound2.329s, configuration7.438s,
  core111.047s. Inbound has no standalone tests; its source is compiled.
- Existing selected modern VMess scenarios passed race90.821s: GCM, GCMUDP,
  ChaCha20, authenticated length with/without termination signal, Mux/MuxUDP.
  This selection does not claim the KCP scenarios.
- Vet passed protocol, all VMess packages and configuration, including final
  added tests. Formatting and diff whitespace checks passed for changed files.
- Account protobuf regenerated identically with protoc33.5/plugin1.36.11:
  SHA256 `08f15e9b0b9ea999cc2ac7281c221a0314f9935a306eb8062c0ac7e23e3529f0`.
- The same final production source compiled locally to a Windows CLI, and its
  version command ran. It is retained outside Git only, not packaged/released;
  reports `e98b95f-dirty`, not an incorrectly relabeled clean future commit.
  Full-feature stripped size35092992 bytes; no size reduction is claimed.
  No foreign-platform distribution builds were requested or run in this batch.

No foreign-OS runtime, whole-repository CI, private-node, Internet, Android,
package/release, SDK/ABI or complete-feature-parity acceptance is claimed.
