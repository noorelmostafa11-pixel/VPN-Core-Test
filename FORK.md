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

This first checkpoint publishes the pinned upstream foundation. Compatibility
additions are still under local verification and are not yet included here.
It is not a claim of complete feature parity, Internet acceptance or stability
on all platforms. Xray's CLI is not yet a drop-in replacement for the native
core's application/SDK interfaces.

Existing upstream workflows are preserved under `.github/upstream-workflows/`,
outside the active Actions directory. No automatic CI, release, scheduled job
or monitoring is enabled by this checkpoint.

## Build

Use the Go version required by `go.mod`:

```text
go build -trimpath -ldflags="-s -w" -o xray ./main
```

Stripping debug symbols does not remove protocol implementations. No size or
performance improvement over upstream is claimed without a measured comparison.
