# Go compatibility batch: six remaining classic Shadowsocks names

Date: 2026-10-16. Source base: `06e99f82979abd8dc5f10224791660ff141439e8`
plus the final production patch in this commit. Go1.27.1 Windows amd64,
GCC16.2 for race. No module dependency/version or default is changed.

## Added and preserved

| Explicit method | Key bytes | IV bytes |
| --- | ---: | ---: |
| camellia-128-cfb | 16 | 16 |
| camellia-192-cfb | 24 | 16 |
| camellia-256-cfb | 32 | 16 |
| idea-cfb | 16 | 8 |
| rc2-cfb | 16 | 8 |
| seed-cfb | 16 | 16 |

RC2 uses 128 effective key bits, not OpenSSL's historical 40/64-bit variants.
SEED means SEED-128 here, never a silent SEED-256 substitution. New protobuf
IDs29..34 are appended; existing enum values, AEAD methods and security defaults
are unchanged. Legacy CFB remains unauthenticated, explicit and single-user
only. It is historical compatibility, not a recommended security setting.
Empty/unknown methods do not select plaintext and per-user lists stay AEAD-only.

## Primitive provenance

Only `cipher/camellia`, `cipher/idea`, `cipher/rc2`, `cipher/seed` and
`tool/alias` from [go-cryptobin](https://github.com/deatil/go-cryptobin)
commit `fa6b1b0cd56abfe1eb4a2e7bf0617b03d86e82fe` are vendored. All 17 initial
source/test/license files were compared with that exact upstream after Go
formatting and local alias import relocation. Upstream root has LICENSE and no
NOTICE file. The [Apache-2.0 license and attribution](../proxy/shadowsocks/internal/cryptobin/LICENSE),
original IDEA derivation notice, per-file modification notices and
[source/change manifest](../proxy/shadowsocks/internal/cryptobin/SOURCES.json)
are preserved. Root Xray MPL-2.0 LICENSE is unchanged.

The packages remain internal; no cryptobin module or native engine is imported.
Upstream SEED-256 source/tests are retained with the small SEED package to avoid
rewriting its implementation; Shadowsocks exposes only its 16-byte key method.
The RC2 constructor additionally rejects keys outside1..128 bytes and effective
bits outside1..1024 before key expansion, rather than panicking on malformed
inputs. Redistributed binaries must retain the applicable third-party license
and attribution; release packaging is not established by these local builds.

## Verification

- Before implementation all12 new client/server configuration cases failed on
  unknown method. They now pass, including exact sizes and per-user guards.
- Known first-block CFB results match [Camellia RFC3713 Appendix A](https://www.rfc-editor.org/rfc/rfc3713.html),
  [RC2 RFC2268 section5](https://www.rfc-editor.org/rfc/rfc2268.html),
  [SEED RFC4269 Appendix B.1](https://www.rfc-editor.org/rfc/rfc4269.html), and
  IDEA's NESSIE vector retained in the pinned upstream tests. All eight RFC2268
  block vectors, including distinct64/128-effective-bit outputs, also pass.
- Constructor tests cover key lengths0..129; RC2 effective-bit rejection and
  valid boundary combinations; exact in-place encryption/decryption; every
  short source/destination length and both inexact-overlap directions. Retained
  primitive tests also run, including IDEA's large known-vector set and bounded
  deterministic RC2/SEED randomized roundtrips.
- All new methods join existing fragmented streams, header-only IPv4/domain/IPv6,
  truncated/empty UDP and user-isolation checks. All `TestFork` cases passed ten
  race-enabled repetitions: shadowsocks18.640s, infra/conf9.150s.
- Full affected race suite, count1, passed: shadowsocks11.012s, four primitive
  packages plus alias1.926..2.360s, shadowsocks_2022 7.976s, infra/conf7.000s,
  core98.616s, UDP test fixture1.669s. Vet passed these packages plus fork/wire.
- Portable Go (`-tags purego`) focused checks passed: shadowsocks3.288s and
  primitive packages1.151..1.203s. This is still Windows runtime.
- The same built Windows CLI passed the full [Go wire fixture](wire/README.md)
  in16.698s: all32 classic names in pinned main, both roles,64 endpoint pairs,
  128 server-first greetings,128 exact200001-byte TCP echoes and576 exact UDP
  echoes32/1400/3800 bytes. No protocol retry or skipped exchange. The already
  supported `chacha20-poly1305` alias is included to cover main's full classic
  list; SS2022 is excluded from this claim. Main's unused none/plain synthetic
  placeholder is unchanged; the fork still uses an empty password for plaintext.
- Full-feature builds passed with CGO_ENABLED=0, trimpath and -s -w for Windows
  amd64, Linux amd64 and macOS arm64. No protocol was removed. Protobuf output
  was byte-reproducible with protoc33.5/plugin1.36.11; changed-file format and
  diff checks passed. go.mod/go.sum and the owner's README are unchanged.

## Evidence and boundaries

Verified Windows CLI SHA256:
`5282f1a4125c36662ce63198754d769dd7b015d3f758cd82ab43c22892515c64`.
It reports base06e99f8-dirty, not a clean future commit. Its35,039,232-byte
stripped size is54,272 bytes above the prior batch; no size reduction is claimed.
Comparison CLI remains exact main b066df1, SHA256:
`2f1da7630fe64d92069e2dc70cb96810e98ad202866151d471cbd760a703cb34`.

Initial wire invocation used relative executable paths, which Go tests resolved
from the package directory rather than the repository root. It failed opening
the file before starting any exchange. The command was corrected to resolved
absolute paths without changing either binary, assertions or timeouts; the
original failure log is retained outside Git along with all verification logs.

Main, releases, private material and owner workflow deletions are untouched.
No workflow, monitor, PR or release was enabled or dispatched. Results establish
local Windows loopback compatibility and cross-compilation only, not Linux/macOS
runtime, Android/packages, Internet, application SDK/ABI, complete feature parity
or a security audit of historical cryptography. Other protocol gaps remain in
[COMPARISON.md](COMPARISON.md).
