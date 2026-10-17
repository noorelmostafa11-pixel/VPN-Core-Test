# Final scoped capability inventory — four-protocol Xray fork

Branch: feature/tcp-mkcp-additive-review-20261017 (development branch only).
Base/owner branch: feature/xray-custom-core at cdc8e0cc3cd6d12a748f0b128aec316f1e74c642.
Date: 2026-10-17. Review of this branch's code: CODE_VERIFIED only, not independent operational interoperability.

## Additive node-input gaps addressed

- TCP HTTP request header through four-protocol node URI, preserving plain TCP.
- mKCP packet camouflage via existing finalmask, seed and six numeric KCP options.
- Bounded XHTTP downloadSettings connection data, including independent XHTTP TLS/REALITY; bounded nested download padding and XMux; unsupported nested files/recursive streams remain rejected.
- Shadowsocks and SS2022 v2ray-plugin *basic in-process WS subset*, optional TLS, host and path. No generic external SIP003 launcher.
- Legacy QUIC numeric tuning for receive windows, stream count, idle/keepalive, preserving original transport's default packet/TLS/cipher policies; fixed false rejection of the shared builder's bbrProfile="standard" default. Not QUIC browser TLS emulation.
- WebSocket and HTTPUpgrade bounded connection-header metadata; block Host, protocol handshake headers and HTTP injection. WebSocket heartbeat.
- gRPC bounded idle/health/window, permitWithoutStream, userAgent metadata.

Full native Xray JSON settings which already worked are not rewritten. Links without added fields retain their original route. Added tests are config-parity and malformed-input fixtures; no fifth remote protocol has been introduced.

## Fundamental/unverified remaining areas: DO NOT claim complete support

1. Generic SIP003 executables, obfs-local/simple-obfs and v2ray-plugin advanced QUIC/mux/mode behavior cannot be treated as standard WebSocket. They require a real independently proven wire implementation and a separate resource/security design.
2. Standalone XDrive from untrusted node URI could control local filesystem resources; it stays full-JSON only. Local-file and process directives cannot be accepted as remote link metadata without explicit application trust management.
3. Explicit Chrome/uTLS client QUIC fingerprinting needs an actual custom QUIC/TLS handshake. Accepting fp=chrome without matching the wire would be incompatible and misleading.
4. QUIC BBR/Brutal congestion tuning is not implemented for the legacy carrier. The mere implicit "standard" BBR profile name from the shared JSON builder does not enable BBR there.
5. Arbitrary and deeply nested XHTTP download configurations are intentionally not accepted from untrusted URI data. In particular nested HTTP headers, local TLS files, sockopts, plugin loading, and recursive downloadSettings remain blocked.
6. Subscription file formats and a complete matrix of technically valid cross-product combinations have NOT been exhaustively implemented or independently verified.

## Testing and release gate

- Go 1.23.2 Linux/amd64 standalone stub harnesses for basic plugin, XHTTP validator, advanced HTTP header/gRPC helper and legacy QUIC settings were rerun with go test -race -count=1 ./... and go vet ./... on 2026-10-17. They are not the original project and do not establish full build/runtime correctness.
- Source/diff review and new Go test fixtures exist for selected parity, defaults, unsupported values and four-protocol inputs. Full Xray Go 1.27.1 build/vet/race runs, independent TCP/UDP wire fixtures, Windows/macOS runtime and connected app acceptance are NOT_VERIFIED.
- Repository's manual-only core-validation workflow has not been dispatched here; no CI status was reported for the staged head at the time checked.
- No merge into the owner's feature/xray-custom-core branch, no application binary, release, production profile or server mutation.

Do not merge or advertise universal protocol/transport completeness until remaining capabilities are properly implemented and the final level-3 acceptance is executed.
