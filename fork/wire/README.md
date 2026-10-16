# Go-only fork/main wire check

For the owner-run GitHub compatibility check, follow
[COMPATIBILITY-CHECK.md](../COMPATIBILITY-CHECK.md). No distributable program
packages are produced. The manual job supplies absolute `-fork-source` and
`-main-source` paths plus `-main-commit`; test peers are temporary fixtures
inside `testing.T.TempDir`, never uploaded, and removed after the test. The main
checkout must match the exact commit and contain its pinned vendor tree.
Only logs, JSON and Markdown test evidence are retained.

The existing explicit-binary mode below remains available for developers.
Source and binary input modes cannot be mixed. Incomplete wire counters make
the test fail, including a filtered run; they are not reported as full coverage.

Build the fork CLI from this checkout and the comparison CLI from the exact
main commit in `../manifest.json`, separately. Then, from the fork root:

```text
go test -race ./fork/wire -run TestMainInteroperability -count=1 -timeout=3m -v -args -fork-binary=/absolute/path/to/fork-cli -main-binary=/absolute/path/to/main-cli -main-commit=b066df12e6e9030a937a3c1313e85cdf62d7bb8f -evidence=/absolute/path/outside/repo
```

This explicitly requested integration test is skipped if neither executable
path is supplied. It uses only Go's standard library and synthetic loopback
credentials, tests both endpoint roles for all 32 classic method names in pinned
main: five classic AEAD methods plus the chacha20-poly1305 alias, nine legacy
AES names and seventeen other classic names (including the none/plain alias).
These are names, not 32 distinct algorithms. The three separate SS2022 methods
are not covered by this fixture.
It requires exact equality for 128 server-first greetings, 128 200001-byte TCP
echoes and 576 UDP echoes (32, 1400 and 3800 bytes). The client waits for the
greeting before sending application bytes.
Protocol exchanges are not retried.

For none/plain the fork uses an empty password. Pinned main requires a nonempty
placeholder even for plaintext, so only that peer receives an unused synthetic
password. Neither endpoint encrypts or authenticates these two names; the
placeholder is not a security feature. All other methods use matching secrets.

The upstream Freedom private-address policy is left unchanged. The server test
configuration allows only 127.0.0.1 and the two ephemeral echo target ports.
The evidence contains process logs, CLI SHA-256 values and actual completed
counters, not assumed totals. Passing does not establish Internet, SDK/ABI or
cross-platform acceptance. No Python or PowerShell runtime is required.
