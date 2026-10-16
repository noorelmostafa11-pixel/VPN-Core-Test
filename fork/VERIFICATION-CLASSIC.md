# Go compatibility batch: eleven other classic method names

Date: 2026-10-16. Base: `2521398169bdd7386840133cae742d6737fcb109` plus the
final production patch in this commit. Go1.27.1 Windows amd64; GCC16.2 for race.
No Go module dependency/version, language toolchain, engine fallback or default
method is added or changed. Crypto implementations use the standard library and
the already pinned golang.org/x/crypto v0.57.0, not a copy of the old engine.

## Added and preserved

`bf-cfb`, `cast5-cfb`, `des-cfb`, `rc4`, `rc4-md5`, `salsa20`, `chacha20`,
`chacha20-ietf`, `table`, `none`, `plain`: client and single-user server TCP/UDP.
The AES stream code is generalized into `legacy_stream.go`; all nine AES modes
and all five existing classic AEAD methods are rechecked. Existing enum IDs are
unchanged; the ten new enum entries cover eleven names because plain aliases none.

These methods are unauthenticated historical compatibility, not recommended
security settings. [Shadowsocks' historical warning](https://shadowsocks.org/doc/stream.html)
applies. In particular table is obfuscation, and none/plain has no encryption or
password authentication. Empty passwords are accepted only for explicit
none/plain; empty or unknown methods never select plaintext. Per-user lists
stay AEAD-only, and runtime legacy/account mixing remains rejected.

Original ChaCha20 keeps an 8-byte nonce and a 64-bit counter. Its high counter
word is placed in the corresponding state word of the existing Go IETF engine;
calls are split at 32-bit low-word wrap. It is not silently downgraded to a
32-bit counter or treated as a 12-byte-nonce alias. Salsa20 uses the existing
Go primitive with an explicit nonce/counter. Both preserve partial-block state
and reject counter reuse at exhaustion using the cipher.Stream panic contract.

Table permutations are immutable and owned by the account, with no global key
cache or maintenance goroutine. Ordinary TCP/UDP operations reuse them. Direct
Cipher callers supplying another key get a separate permutation; they cannot
poison the account's table.

## Verification

- Before the patch all 22 new client/server configuration cases failed. The
  successful version also checks empty/unknown method, empty password and
  per-user-list rejection policies.
- New and previous focused tests passed ten race-enabled repetitions: classic
  and AES/AEAD vectors/framing, exact key/IV sizes, fragmented streams,
  header-only IPv4/domain/IPv6 targets, empty/truncated UDP, RC4-MD5 derivation
  and packet-state reset, concurrent table golden digest, alternate-key table
  isolation and original ChaCha carry past 2^32 against an independent test-only
  original-state oracle. ARX exhaustion checks cover the final usable block and
  ensure an overlong call changes neither output nor counter.
- Salsa20 matches the 131072-byte ECRYPT set6 folded vector, retained in the Go
  crypto tests, with 137-byte fragments. RC4 matches [RFC6229's 128-bit vector](https://www.rfc-editor.org/rfc/rfc6229.html),
  CAST5 the RFC2144 vector, plus published Blowfish, DES and ChaCha vectors.
- Affected `-race` suite passed: shadowsocks10.468s, shadowsocks_2022 cached,
  infra/conf8.706s, core86.244s, UDP test fixture cached. Vet passed those five
  packages and fork/wire. Final focused count10: shadowsocks26.409s,
  infra/conf11.955s; the UDP fixture count10 also passed in the earlier focused run.
- The Go-only [wire check](wire/README.md) passed16.039s: 25 method names in both
  roles, 50 pairs, 100 server-first greetings, 100 exact 200001-byte TCP echoes,
  450 exact UDP echoes. No protocol retry, skipped case or relaxed deadline.
- `-tags purego` golden/fragmentation, Salsa ECRYPT, original ChaCha carry and
  ARX exhaustion checks passed5.783s on Windows; this tests the library's
  portable Go implementation, not execution on a foreign OS.
- Full-feature Windows amd64 build and Linux amd64/macOS arm64 cross-builds
  passed with CGO_ENABLED=0, trimpath and -s -w. Protobuf regeneration was
  byte-reproducible with protoc33.5/plugin1.36.11; changed-file format/diff checks
  passed. go.mod/go.sum are unchanged.

## Initial failures retained in local evidence

The first ChaCha golden literal had an odd trailing hex nibble and failed
before encryption. The fixture was corrected to the published 32-byte prefix;
both ChaCha variants, the independent counter oracle and all actual wire cases
remain enabled. No production assertion or expected algorithm was substituted.

The first full wire run passed all 46 encrypted/obfuscated pairs but the pinned
main CLI rejected empty-password none/plain settings before listening:
SERVER_PASSWORD_INVALID / ROUTE_OUTBOUND_INVALID. Only that peer's fixture now
supplies its required unused synthetic placeholder; the fork still runs both
plaintext roles with an empty password. The original main binary and all
greeting/byte/deadline assertions are unchanged. Corrected full run passes all
50 pairs. Neither a main-code fix nor password authentication is claimed.

## Provenance and boundaries

Verified Windows CLI SHA256:
`025e6be586be0388f90cea9fbbd33eaca691b5b3314d01c4e38e21a3fefcfade`.
It was built from base25213981 plus the final dirty production patch, not
mislabeled as a clean future commit. The same binary passed the final wire run.
Stripped full-feature size: 34,984,960 bytes, 47,616 bytes above the prior batch;
no size reduction is claimed and no protocol was removed.

Comparison uses exact main b066df1; later owner-only workflow removals do not
change that production source. Main, owner README edits, private material and
releases are untouched. No workflow was enabled, dispatched or monitored.

These are local Windows runtime and portable implementation checks, not full
repository tests, foreign OS runtime, Android/package, Internet or application
SDK/ABI acceptance. Six other classic method names and additional protocol gaps
remain in [COMPARISON.md](COMPARISON.md).
