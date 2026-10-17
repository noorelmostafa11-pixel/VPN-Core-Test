# One-batch gap implementation: opt-in Legacy QUIC congestion control

Branch: feature/tcp-mkcp-additive-review-20261017
Parent: 466c419a8f300c5c2579867bbd761102ceaa7e83

## Real runtime capability added

The retained standalone legacy QUIC transport can now explicitly select BBR (standard/conservative/aggressive) or force-brutal (both upload/download speeds required, each 65536..1073741824 bytes/sec), in addition to its preexisting default Reno. This reuses the checked-in `transport/internet/quic/congestion` sender implementations already referenced by XHTTP/H3. The selected controller is applied to outgoing QUIC connection after successful dial and incoming QUIC connection after Accept, before handling streams. The only new controls are opt-in `finalmask.quicParams` or `quicParams` node share-link fields. All original no-congestion configurations, handshake, per-packet encryption, TLS and packet header behavior retain the prior code path. Only an explicit `congestion:"bbr"` or `congestion:"force-brutal"` replaces Reno.

The existing Full-JSON bandwidth parsing interprets `8mbps` as 1,048,576 bytes/sec and `16mbps` as 2,097,152 bytes/sec; the node importer delegates to the same Bandwidth.Bps conversion. This does not enable Hysteria remote VPN proxy handling or any fifth protocol.

## Test evidence and remaining gaps

CODE_VERIFIED by source review with new Go test fixtures for positive/negative controller profiles, bounded rates and all four node URI schemes. No complete Go 1.27.1 module build was available during this checkpoint; all repository Go tests, external QUIC wire interoperability, platform acceptance and throughput comparisons remain NOT_VERIFIED. This is an actual controller hook, not merely acceptance of a parameter.

Not implemented in this batch: Chrome/uTLS QUIC fingerprinting; SIP003 external execution and actual simple-obfs/obfs-local wire emulation; XDrive untrusted-URI process/file directives; arbitrary XHTTP recursive download settings; unenumerated subscription dialects. Do not claim universal completeness or merge into owner branch until full test gate and independent protocol traces succeed.
