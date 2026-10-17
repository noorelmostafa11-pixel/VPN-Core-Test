# VPN-Core-Test: custom Xray branch

This branch starts from official XTLS/Xray-core v26.10.10 (a prerelease),
commit `701af60772cda123492f86e383e1fdba066614a9`. Upstream history,
attribution and the MPL-2.0 license are preserved. The Go module path stays
unchanged to keep upstream imports and future merges compatible.

## Scope and language policy

- Core implementation and new executable test/build tools are written in Go.
- No Python or PowerShell toolchain is added for custom-fork development.
- Upstream configuration, protobuf definitions, documentation and original
  packaging metadata retain their native formats; language statistics are not
  hidden or relabeled to make the branch appear Go-only.
- The comparison reference is VPN-Core-Test `main` at
  `b066df12e6e9030a937a3c1313e85cdf62d7bb8f` (0.5.25-go).
  The deleted native-core branch is not recreated or used as the reference.
- Main, existing releases and private application/node material are untouched.

## Checkpoint

One connection-data integration point now owns automatic capability selection:
`conf.ResolveNode`. URI input, a versioned JSON node description (`.node`) and
the Go description API use that same point before the normal Xray configuration
and runtime lifecycle. Original full JSON/protobuf readers keep their meaning.
[Architecture, supported capabilities and checks](fork/VERIFICATION-IN-PATH-ADDONS.md).

Standalone legacy QUIC is now an independent registered transport with packet
AEAD/camouflage, normal TLS or its explicitly selected historical internal-
certificate mode. URI metadata selects it automatically. Historical protobuf
packet-header messages are also accepted without changing the JSON/URI path.
Browser fingerprints and advanced tuning remain unsupported, not substituted.
[Transport checks](fork/VERIFICATION-LEGACY-QUIC.md) and
[typed-header checks](fork/VERIFICATION-QUIC-TYPED-HEADERS.md).

Original-behavior preservation is a prerequisite for further additions.
Existing upstream configurations retain their ignored fields and AUTO fallbacks;
ambiguous legacy VMess/SOCKS choices now use a separate `legacySettings` block.
The original Shadowsocks server-first behavior fix is opt-in for original
methods. [Selection rules and baseline comparison](fork/VERIFICATION-PRESERVATION.md).

Node-URI input now selects implemented support automatically from the node's
protocol/transport/security metadata, with no per-feature enable switches.
Use a `.uri` input file or the Go URI reader; original JSON behavior stays
unchanged. Low-level legacy fields are generated internally, not required in
node links. [Automatic selection and its current scope](fork/VERIFICATION-NODE-SELECTION.md).

The first compatibility addition is explicit Shadowsocks `aes-192-gcm`, including
client, server and multi-user server configuration, TCP and UDP. The existing
four classic AEAD methods remain supported. See [verification](fork/VERIFICATION.md)
for local checks, prerequisites, failures and acceptance boundaries.

The next batch adds the nine explicit historical AES stream methods: CFB, CTR
and OFB, each with 128/192/256-bit keys, for single-user TCP/UDP endpoints.
These methods lack authentication and are for compatibility, not a recommended
security choice. They do not change defaults and cannot share a listener with
other accounts. [Details and checks](fork/VERIFICATION-LEGACY-AES.md).

The third batch adds `bf-cfb`, `cast5-cfb`, `des-cfb`, `rc4`, `rc4-md5`,
`salsa20`, original `chacha20`, `chacha20-ietf`, `table`, `none` and `plain`.
They are explicit compatibility choices only, not recommended security settings;
`table` is obfuscation and `none/plain` is entirely unencrypted. No implicit
plaintext fallback exists. [Checks and limits](fork/VERIFICATION-CLASSIC.md).

The fourth batch completes the six remaining classic names in main:
`camellia-128-cfb`, `camellia-192-cfb`, `camellia-256-cfb`, `idea-cfb`,
`rc2-cfb` and `seed-cfb`. Only scoped Go primitive packages are vendored, with
their Apache-2.0 license, source pin and modification notices. The full 32-name
classic list, including aliases, passed local interoperability in both roles.
This is not 32 distinct algorithms or acceptance of the separate SS2022 wire
protocol. [Verification and source attribution](fork/VERIFICATION-BLOCK-CFB.md).

SOCKS4 and SOCKS4a TCP CONNECT outbounds are now available explicitly, including
local IPv4 resolution for SOCKS4 and remote domain resolution for SOCKS4a.
SOCKS5 stays the default; unsupported UDP/IPv6/password semantics are rejected
instead of substituted. [Settings and local checks](fork/VERIFICATION-SOCKS4.md).

VMess `aes-128-cfb`, `none` and TCP-only `zero` body modes are explicit choices
inside `legacySettings`, with modern AEAD headers when its alterId is zero.
Inbound use requires a per-user opt-in in that same block;
modern defaults are retained. [Body details](fork/VERIFICATION-VMESS-BODY.md).

Explicit `legacySettings.alterId: 1..64` selects historical VMess timestamp/HMAC headers
on outbounds and opts an inbound user into accepting them. Zero remains modern
AEAD, with no automatic downgrade. Legacy header/body permission is separate;
CFB/none bodies still need `legacySettings.allowLegacyBody: true` on the inbound user.
An old top-level `alterId` remains ignored, and top-level `none`/`zero`/CFB/unknown
security names still select AUTO, exactly as on pinned upstream. This is
an old, weaker protocol for compatibility, not a security recommendation.
[Settings, bounds and local checks](fork/VERIFICATION-VMESS-LEGACY-HEADER.md).

Standalone legacy HTTP/2 is restored as `http`/`h2`/`http2`, with explicit
cleartext prior-knowledge `h2c` as well as TLS. It uses its own `httpSettings`
and raw HTTP/2 request/response bodies, not an XHTTP alias. Host/path/method
validation, server-first streaming, upload half-close and cancellation are
implemented. The HTTP/2 + REALITY pairing is now available as an added path;
existing REALITY transports are unchanged.
[REALITY pairing, ALPN semantics and checks](fork/VERIFICATION-HTTP2-REALITY.md).
[Settings, local results and known ECH test failure](fork/VERIFICATION-HTTP2.md).

This is not complete feature parity, Internet acceptance or stability on all
platforms. Xray's CLI is not yet a drop-in replacement for the native core's
application/SDK interfaces. See the [comparison backlog](fork/COMPARISON.md).

Existing upstream workflows are preserved under `.github/upstream-workflows/`,
outside the active Actions directory. A separate manually requested
[compatibility-only workflow](fork/COMPATIBILITY-CHECK.md) is available through
the existing **Build & Test** page: select `feature/xray-custom-core` before Run
workflow. It runs the repository tests and fork/main comparisons on three OSes;
there are no package, mobile, release, push, scheduled or monitoring jobs.
The custom Go-only policy is also
recorded in [AGENTS.md](AGENTS.md). GitHub's repository language bar is calculated
from the default branch; keeping main unchanged does not update that bar to this
branch's file composition.

## Build

Use the Go version required by `go.mod`:

```text
go build -trimpath -ldflags="-s -w" -o xray ./main
```

Stripping debug symbols does not remove protocol implementations. No size or
performance improvement over upstream is claimed without a measured comparison.
