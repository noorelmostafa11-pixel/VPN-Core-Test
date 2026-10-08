# vpn-core 0.4.8

Additive URI import compatibility preserves the original URI, original query values and node ID. Complete XHTTP objects can also use encoded plus whitespace, single quoted strings or a second URL encoding layer. Observed VLESS `none` suffixes, REALITY `tcp#` suffixes and semicolon-prefixed REALITY field aliases now resolve through explicit compatibility paths. Canonical values keep priority; incomplete JSON and missing or invalid credentials stay subject to the existing validators. See [SUPPORT-0.4.8.md](SUPPORT-0.4.8.md).

Each workflow run resolves the latest Pre main commit once and downloads its four protocol files. Linux/Windows inspection, all 15 network shards and the Windows package share those exact inputs. Shard and report totals follow the downloaded inventory; the old network fixture compares overlapping IDs only.

## Previous 0.4.5 connection coverage

Adds the `randomizednoalpn` TLS fingerprint found in the 2026-10-07 Pre snapshot, including verified byte transfer on TLS 1.2/1.3 and WebSocket, concurrent sessions and certificate-name rejection. A misfiled XHTTP options object in `fm` now reports `FINALMASK_STRUCTURE_INVALID`; an unimplemented TCP mask inside a valid mask list still reports `FINALMASK`.

Both randomized presets keep TLS 1.3 available instead of occasionally generating TLS-1.2-only templates. Independent OpenSSL tests verify 1,024 reproducible handshakes and matching echoes across TLS-1.2-only and TLS-1.3-only servers, including absent ALPN on the NoALPN preset.

Current Pre support is pinned separately from the unchanged 0.4.2 baseline: 71,755 rows, 70,787 supported, 968 invalid, zero missing features in valid configurations. CI verifies file integrity, every row/node ID and expected support counts on Linux and Windows. These are inspection results, not successful public-node connections. See `PRE-COVERAGE-0.4.5.md`.

## Previous 0.4.4 build and API changes

Unified laptop/GitHub source builds for Windows amd64, Linux amd64 and four Android ABIs, with isolated output folders, pinned tools, hashes and provenance. Windows keeps Schannel/CNG; production POSIX uses the existing verified TLS provider and Go standard cryptographic primitives. Protocol and node values remain unchanged.

Adds a blocking shared C API with single-run protection and stop/restart, and loads the provider beside its owning executable/library. Android libraries are SOCKS core components: JNI, VPNService socket protection, TUN and APK integration are not implemented here. Cross compilation is recorded separately from runtime validation.

GitHub validates production desktop binaries, source regressions, Windows readiness-file IO retries, Android ABI builds on Linux and Windows, and independent TLS/protocol peers on an Android x86_64 emulator. Physical ARM device and application VPN integration remain outside this coverage.

Run 37600257138 for 0.4.3 completed all 72767 records: 1570 PASS, 70178 FAIL, 1019 PARSE_INVALID. No OUTPUT_DRAIN_TIMEOUT; two runner readiness-file read failures are documented in docs/RUN-37600257138.md. Live-node differences do not alone prove a repair caused recovery.
