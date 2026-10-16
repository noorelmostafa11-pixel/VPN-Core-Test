# Xray fork self-compatibility wire test

Both the client and Shadowsocks server run as separate processes of **the same
Xray fork executable**. No checkout, executable, protocol implementation or
data from a second engine is used. Tests use synthetic loopback TCP/UDP only.

The manual GitHub Actions job builds Xray from the selected fork commit and runs:

```text
go test -race ./fork/wire -run '^TestXraySelfCompatibility$' -count=1 -timeout=12m -v -args -binary=/absolute/path/to/xray -evidence=/absolute/path/outside/repo
```

For local use, supply `-source=/absolute/path/to/this/fork` instead of `-binary`
to build the Xray executable into a temporary directory. When neither is
supplied, this integration test is skipped during the general `go test ./...`
suite and run separately by the workflow's dedicated `wire` stage. That wire
stage must complete; skipped, partial or failed exchanges do not count as passes.

The fixture covers **all 32 currently registered classic Shadowsocks method
names** (including legacy aliases). Expected completed results are 32 Xray
client/server pairs, 64 server-first greetings, 64 exact 200001-byte TCP echoes
and 288 UDP echoes at 32, 1400 and 3800 bytes. It checks exact TCP/UDP
payloads, source endpoints and server-first greeting contents. Protocol
exchanges are never retried.

For `none` and `plain`, both fork processes use an empty password. These
methods do not encrypt or authenticate traffic; they are legacy compatibility
only. The server fixture explicitly allows only synthetic loopback echo ports,
without changing the production Freedom private-address policy.

Reports record test logs, a SHA-256 hash of the exact Xray executable and
completed counters. The executable is temporary and never included in the
uploaded artifact. No releases, Android packages or automatic runs occur.

**Boundary:** same-fork self-compatibility is not interoperability with a
different client/server implementation, real Internet or private-node
acceptance. SS2022 has separate package tests but is not covered by this
classic-wire fixture. No mobile SDK/ABI or Android integration is tested.
