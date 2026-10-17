# Larger additive batch: level-3 handoff (NOT VERIFIED)

Project: noorelmostafa11-pixel/VPN-Core-Test
Working branch: feature/tcp-mkcp-additive-review-20261017
Baseline before this batch: cbb51ab04d5be3ad9aab7c1ed4b28d2663d73036
Pre-gate HEAD: f27962336074ca9c348a52662e0fa7fd2ffc5396

## New opt-in capabilities in this batch

1. WebSocket / HTTPUpgrade share-node early data: explicit ed/earlyData/early-data query, bounded 0..2048 bytes, maps to native transport's existing path-encoded ed wire setting. Conflicts with path's pre-existing ed reject; absent field preserves original URI interpretation. Tests: infra/conf/node_earlydata_test.go.
2. Legacy HTTP/2 node URI, versioned node JSON and VMess JSON share envelopes: httpMethod, httpHeaders, httpReadIdleTimeout, httpHealthCheckTimeout, delegated to original HTTPConfig.Build/http.Config.Validate. Tests: infra/conf/node_http2_extensions_test.go.
3. Strict opt-in subjson/node-list JSON arrays of NodeDescription, 1..128 entries, 1MiB maximum input, per-entry original node parser, unique outbound tags and atomic error handling. No arbitrary local config or additional remote VPN protocols. Tests: infra/conf/serial/node_list_json_test.go.
4. Explicit subscription-file selection through core.GetFormatByExtension and main/run.go directory filter: .sub/.subscription = the existing text/Base64 list importer, .subjson/.node-list = the new strict JSON array importer. Default extension and directory behavior for original .uri/.node/.json/.yaml/.toml unchanged. Tests: core/config_subscription_formats_test.go.

All changes remain in the existing four remote protocol families: VLESS, VMess, Trojan, Shadowsocks (including SS2022). No changes to packet encryption, VPN protocol implementation, TLS certificate bypass, E2 or A1, Android, release pipelines, main or the owner's feature/xray-custom-core branch.

## Final gate: owner executes manually

Use GitHub Actions 'Build & Test' (file .github/workflows/core-validation.yml, workflow_dispatch) and select the working review branch HEAD from this report's successor commit. It is manual only, not triggered by this task.

The workflow specifies Go 1.27.1 and Windows 2025 / Ubuntu 24.04 / macOS 15. It performs:
- go run ./fork/check prepare
- go run ./fork/check suite
- go run ./fork/check vet
- go run ./fork/check build
- go run ./fork/check wire
- go run ./fork/check summary

The per-OS reports are artifacts, not deployable binaries. Independently validate retained four-protocol TCP/UDP wire behavior with real counterpart implementations, new WS/Upgrade early data and HTTP/2 headers, previously staged TCP/mKCP/XHTTP, SS+SS2022 plugin basic WS and Legacy QUIC default/BBR/Brutal. Confirm XHTTP upload/download independently, certificate policies, older links, malformed inputs, application-side SDK and client behavior before considering merge.

Evidence so far: CODE_VERIFIED source and pinned GitHub diff; regression tests added, not executed in the full original Go module. CI checks for the pinned staged heads were absent at inspection. Windows/Linux/macOS runtime and independent wire interoperability: NOT_VERIFIED.

## Outstanding work that this batch does not claim

Authentic simple-obfs/obfs-local and arbitrary SIP003 executable compatibility; QUIC client uTLS browser-fingerprint impersonation; arbitrary untrusted XDrive local resource import; every vendor subscription dialect; every nested XHTTP setting. Never silently alias unsupported wire formats, spawn remote-supplied binaries or weaken certificate validation in order to claim completion.

No merge or production rollout without reviewed complete level-3 acceptance.
