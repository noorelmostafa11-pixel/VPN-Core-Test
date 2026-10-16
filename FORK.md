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

The first compatibility addition is explicit Shadowsocks `aes-192-gcm`, including
client, server and multi-user server configuration, TCP and UDP. The existing
four classic AEAD methods remain supported. See [verification](fork/VERIFICATION.md)
for local checks, prerequisites, failures and acceptance boundaries.

This is not complete feature parity, Internet acceptance or stability on all
platforms. Xray's CLI is not yet a drop-in replacement for the native core's
application/SDK interfaces. See the [comparison backlog](fork/COMPARISON.md).

Existing upstream workflows are preserved under `.github/upstream-workflows/`,
outside the active Actions directory. No automatic CI, release, scheduled job
or monitoring is enabled by this checkpoint. The custom Go-only policy is also
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
