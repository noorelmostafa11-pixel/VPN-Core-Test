# Go compatibility batch: nine legacy AES methods

Date: 2026-10-16. Go 1.27.1, Windows amd64; GCC 16.2 for race checks. Builds
retain full upstream protocol registration. No dependency, fallback engine,
Python tool or PowerShell tool is added. Comparison main remains the exact
0.5.25-go commit in [manifest.json](manifest.json).

## Implementation and limits

- AES-CFB128, CTR and OFB, each with 128/192/256-bit keys and 16-byte IVs.
  Method names are `aes-128-cfb` through `aes-256-ofb`, not CFB8 or CFB1.
- Explicit client or single-user server settings only. No default is changed;
  per-user lists stay AEAD-only. Runtime account insertion rejects legacy/AEAD
  and legacy/legacy mixtures in both insertion orders, without mutating the list.
- Standard Go AES/stream implementations; TCP keeps stream state across writes,
  UDP starts a fresh stream for every packet. Existing enum IDs are unchanged.
- An IV-only prelude allows legacy header-only requests and server-first replies
  without imposing the AEAD 50-byte prefix. AEAD keeps its existing prelude.
- Bounds checks reject truncated IVs/AEAD length headers before slicing. Accounts
  using the same password but different methods no longer compare equal.

These are unauthenticated historical methods, not recommended security choices.
See the [Shadowsocks historical warning and wire specification](https://shadowsocks.org/doc/stream.html).
No claim of wrong-password/tamper authentication is made for these ciphers.

## Checks

- Reproduction before production edits: all 18 new client/server configuration
  cases failed with unsupported method. Assertions were retained.
- New focused tests, ten race-enabled repetitions: exact key/IV sizes, config,
  multi-user rejection, NIST golden first blocks, fragmented streams, short
  key/IV rejection, all short UDP-IV lengths, header-only IPv4/domain/IPv6
  targets, UDP framing and validator insertion/deletion/isolation.
- Golden data are from [NIST SP800-38A appendix F](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf),
  sections F.3.13/15/17, F.4.1/3/5 and F.5.1/3/5. Whole-stream protocol checks
  against the independently built main CLI also distinguish CFB from OFB.
- The affected race suite covers `proxy/shadowsocks`, `proxy/shadowsocks_2022`,
  `infra/conf`, `core` and `testing/servers/udp`. Vet covers those plus `fork/wire`.
- Expanded Go [wire check](wire/README.md): all five existing AEAD and nine new
  legacy methods in both roles. Exact totals: 28 pairs, 56 server-first greetings,
  56 200001-byte TCP echoes, 252 UDP echoes. No protocol retry or skipped case.
- Full-feature Windows amd64 build and Linux amd64/macOS arm64 cross-builds use
  `CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"`. Foreign builds are not foreign
  runtime acceptance. Protobuf regeneration and changed-file diff checks pass.

## Failures investigated, not retried away

The expanded greeting test initially failed for all five existing AEAD methods
when the fork was the client. The same exact greeting failure reproduced with
the previous unmodified published fork binary. Nine new legacy methods already
passed in both roles. An empty initial inbound buffer was being passed to the
AEAD writer as an end marker. The Shadowsocks client's initial-copy step now
ignores only empty input and retains real initial data; a unit test covers all
five AEAD methods. Greeting, payload and deadline checks remain unchanged.

The affected race run caught a separate inherited test-fixture race:
`testing/servers/udp.Server.accepting` was written by both the reader goroutine
and Close. The fixture now exits on socket read failure and Close joins its
reader through a completion channel. Its new test checks immediate-close and
echo-then-close schedules, with ten repetitions. This is test infrastructure,
not a production UDP transport fix. No race check was disabled.

The verified executable was built from base `5778396d` plus these final dirty
production edits; it is not mislabeled as a clean future commit. Local failed
and final logs remain outside Git. The stripped Windows CLI is 34,937,344 bytes,
10,752 bytes above the preceding full-feature build; no size reduction is claimed.
No main, private nodes, application integration, CI run, release or PR changed.

Remaining non-AES historical methods, other missing protocols, platform runtime
and Internet/application/SDK acceptance remain outstanding; see [COMPARISON.md](COMPARISON.md).
