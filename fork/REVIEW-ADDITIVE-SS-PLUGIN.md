# Additive Shadowsocks SIP003 WebSocket subset — review checkpoint

Source baseline: `VPN-Core-Test`, branch `feature/tcp-mkcp-additive-review-20261017`, commit `f4da7b2e2d96d4bb27fa42db30cb32a6027d0949` (2026-10-17).

## Scope and deliberate limits

The original remote protocol count stays exactly four: VLESS, VMess, Trojan, Shadowsocks (including SS2022). For **Shadowsocks node inputs only**, the existing `plugin=` SIP003 share-link parameter can now select an **in-process, basic WebSocket subset** of `v2ray-plugin`. No external binary, shell, subprocess, filesystem lookup, download or new proxy protocol is used.

Supported form: `plugin=v2ray-plugin[;mode=websocket][;tls][;host=domain-or-IP][;path=/absolute-path]`. The original Xray WebSocket transport and TLS verifier are reused, including SNI from the declared host when `tls` is set. Plain `v2ray-plugin` defaults to WebSocket without TLS because no TLS flag was supplied. `mode=websocket` is optional. URI percent-encoding applies to the entire parameter value. Both classic Shadowsocks and SS2022 retain their original ciphertext and builders.

Not covered: generic SIP003 executable plugins; `obfs-local` / `simple-obfs`; `v2ray-plugin` mux, QUIC, TLS certificate loading, other transport modes, raw command arguments or advanced plugin-specific HTTP options. They are **explicitly rejected** rather than silently interpreted. Existing full JSON and non-plugin node inputs remain unchanged.

Mixed `plugin` plus explicit transport/security metadata is rejected instead of preferring either side. The parser rejects unsupported keys, duplicated/case-ambiguous options, invalid hosts/paths, embedded control characters, and opt-in attempts to skip TLS validation. Errors do not contain secrets.

## Review levels

1. **Source/isolated validator**: Go formatting, `go test -race -count=1 ./...` and `go vet ./...` executed on a standalone standard-library-only stub harness, Go 1.23.2 Linux/amd64. These tests cover mapping, TLS flag, default, rejection, no-plugin behavior, and encoded control path. They do not build Xray itself.
2. **Configuration parity**: repository regression tests **authored but not yet executed in complete Xray module**. They compare the generated stream configuration to explicit existing WS/TLS settings for classic SS and SS2022, verify URI versus versioned JSON-node, compare Shadowsocks base64 share forms, and assert other protocols, unsupported plugins and older no-plugin profiles are not reinterpreted.
3. **Deferred to final combined validation: NOT_VERIFIED** — independent `v2ray-plugin` endpoint wire agreement, end-to-end SS classic/SS2022 TCP/UDP behavior as applicable, Windows/Linux/macOS full-module race/vet/build and four-protocol regression suite. In-process WS config parity is **not** yet proof of compatibility with third-party SIP003 processes.

No changes to the project's established transport or proxy runtime, no fifth VPN protocol, no merging into the owner's existing core branch, and no production deployment.
