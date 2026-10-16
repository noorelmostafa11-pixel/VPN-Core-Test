# Local verification: first Go compatibility addition

Date: 2026-10-16. Host: Windows amd64. Go: 1.27.1. Race toolchain: GCC 16.2.
Production source is the AES-192-GCM patch and unreachable-code cleanup in this
feature commit. The measured executables were built before committing, with VCS
metadata identifying foundation `22f40ca` plus dirty changes. They were rebuilt
after the final production edit; they are not mislabeled clean commit builds.
The owner's concurrent README-only edit `e632314e` is preserved unchanged.

## Reproduction and checks

- Before the cipher patch, the new client, server and multi-user configuration
  cases all failed against the pinned upstream with an unsupported method.
- After the patch, configuration, independently derived AES-192-GCM golden wire,
  negative authentication and TCP/UDP framing tests passed. Final focused new
  tests run with `-race -count=10`.
- `go test -race ./proxy/shadowsocks ./proxy/shadowsocks_2022 ./infra/conf ./core
  -timeout=3m` passed for the affected upstream packages.
- `go vet ./proxy/shadowsocks ./proxy/shadowsocks_2022 ./infra/conf ./core
  ./fork/wire` passed after the inherited unreachable statements were removed.
  The unconditional upstream rejection of legacy reverse configuration remains;
  a new regression test checks that rejection and ordinary configuration.
- The Go-only [wire check](wire/README.md), with explicit independently built
  CLIs, passed for five AEAD methods in both endpoint roles: 10 pairs, 20 exact
  200001-byte TCP echoes and 90 exact UDP echoes. Main was built from pinned
  `b066df12e6e9030a937a3c1313e85cdf62d7bb8f`, not the deleted branch.
- Full-feature CLI compilation passed with `CGO_ENABLED=0`, `-trimpath` and
  `-ldflags="-s -w"` for windows/amd64, linux/amd64 and darwin/arm64. Linux and
  macOS results are cross-compilation, not execution on those operating systems.
- Protobuf regeneration is byte-reproducible with protoc 33.5 and protoc-gen-go
  1.36.11. Existing enum numbers are unchanged. Changed/new cipher and wire
  sources are formatted; `git diff --check` passes.

## Failures and prerequisites retained in local evidence

The initial full configuration-package test lacked `resources/geoip.dat` and
`geosite.dat`; the assertions were not disabled. Upstream's configured asset
provider, Loyalsoldier/v2ray-rules-dat, was pinned to commit
`a2d310e1de9ba35757f1633dda231192d114a306`; both downloads were verified against
their published SHA-256 values. These ignored test assets are not committed.

The first loopback server fixture hit upstream's default private-address block,
including for all four unmodified methods. The replacement Go fixture explicitly
allows only 127.0.0.1 and its two echo target ports. No production default,
payload equality, deadline or retry policy was weakened. The retired local
Python harness was never committed.

The inherited source also contained statements after an unconditional return in
`infra/conf/xray.go`, reported by vet. Only those unreachable statements were
removed; legacy reverse was not enabled. The first whole-tree formatting check
reported differences in untouched upstream working-copy files. No wholesale
reformat was published and no whole-tree formatting success is claimed.

## Size and boundaries

Same-toolchain stripped full-feature Windows builds: unmodified upstream
34,926,080 bytes; custom fork 34,926,592 bytes. This addition costs 512 bytes in
that comparison; it is not a binary-size improvement. No supported protocol was
removed. No private nodes, application files, credentials or profiles were read
or published. No automatic CI, remote run, release or PR was created.

These checks do not establish full repository test coverage, runtime acceptance
on Linux/macOS, Android packaging, application/SDK integration or real Internet
acceptance. Remaining main features are listed in [COMPARISON.md](COMPARISON.md).
