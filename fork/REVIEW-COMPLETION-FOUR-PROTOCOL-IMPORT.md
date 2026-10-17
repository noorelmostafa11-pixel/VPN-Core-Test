# Four-protocol additive import completion and audit checkpoint

Branch: feature/tcp-mkcp-additive-review-20261017.
Parent: 57e141d0838a9388b32bf4e107bfb6570bb7585e.

## Confirmed compatibility bug fixed
The original Full-JSON StreamConfig.Build inserts bbrProfile="standard" whenever finalmask.quicParams is supplied (even if the user did not request BBR). The staged legacy QUIC runtime rejected this harmless implicit standard profile, preventing the tuning introduced in the preceding commit from working. The runtime validator now accepts the exact normal "standard" default but continues to reject real nonstandard BBR profiles and every actual congestion-control override. The existing quicConfig() baseline and packet/TLS implementation are unchanged.

## Additional opt-in connection import
WS and HTTPUpgrade node links accept transport-specific wsHeaders/httpUpgradeHeaders JSON objects, restricted to HTTP token header names and bounded newline-free values, with Host authority kept exclusively in the original host parameter. WS supports optional wsHeartbeatPeriod (0..3600); gRPC supports optional grpcIdleTimeout, grpcHealthCheckTimeout, grpcInitialWindowSize, grpcPermitWithoutStream and grpcUserAgent. Existing full Xray transport implementations and default links are not changed. VMess JSON envelope accepts header-object parameters as objects instead of requiring an escaped string.

Changes are available only when these extra fields are explicitly supplied for the matching transport; unknown metadata remains an error, and the four remote protocol families remain unchanged. Go-config/protobuf runtime implementations and any certificate policies are not modified by this feature.

## Audit / remaining limits
- Level 1: source verified against pinned branch parent and Go standard-library-only validator planned. No complete Go 1.27 module build may be claimed from source inspection.
- Level 2: regression fixtures authored for four-protocol WS/HTTPUpgrade parity, gRPC knobs, VMess JSON envelope, versioned JSON-node, malformed/unsafe headers and default preservation. Execution in full Xray source is NOT_VERIFIED.
- Level 3: combined end-to-end independent-wire and cross-platform matrix, explicitly deferred by owner; NOT_VERIFIED.

**Deliberate unsupported areas:** generic SIP003 external binaries, obfs-local/simple-obfs and non-WS plugin modes require independently implemented and tested wire protocols, not aliasing to WebSocket. XDrive node URI would admit filesystem-directed configuration and remains full-JSON-only. QUIC browser uTLS requires a matching QUIC TLS handshake implementation; accepting such a name would lie about interoperability. Legacy QUIC BBR/Brutal needs separately validated congestion control. A finite set of parser features must not be presented as universal Internet compatibility.
