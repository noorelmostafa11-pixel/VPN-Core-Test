# vpn-core 0.4.4

Unified laptop/GitHub source builds for Windows amd64, Linux amd64 and four Android ABIs, with isolated output folders, pinned tools, hashes and provenance. Windows keeps Schannel/CNG; production POSIX uses the existing verified TLS provider and Go standard cryptographic primitives. Protocol and node values remain unchanged.

Adds a blocking shared C API with single-run protection and stop/restart, and loads the provider beside its owning executable/library. Android libraries are SOCKS core components: JNI, VPNService socket protection, TUN and APK integration are not implemented here. Cross compilation is recorded separately from runtime validation.

GitHub validates production desktop binaries, source regressions, Windows readiness-file IO retries, Android ABI builds on Linux and Windows, and independent TLS/protocol peers on an Android x86_64 emulator. Physical ARM device and application VPN integration remain outside this coverage.

Run 37600257138 for 0.4.3 completed all 72767 records: 1570 PASS, 70178 FAIL, 1019 PARSE_INVALID. No OUTPUT_DRAIN_TIMEOUT; two runner readiness-file read failures are documented in docs/RUN-37600257138.md. Live-node differences do not alone prove a repair caused recovery.
