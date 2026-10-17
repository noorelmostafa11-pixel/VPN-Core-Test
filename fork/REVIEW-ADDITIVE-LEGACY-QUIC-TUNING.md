# Additive bounded Legacy QUIC tuning — staged integration review

Project: VPN-Core-Test, branch feature/tcp-mkcp-additive-review-20261017. Parent: 934aacd6cde028a516ba26d8c53a8b3579eb00c2.

## Opt-in scope

Four supported remote protocol families remain VLESS, VMess, Trojan and Shadowsocks (including SS2022). Legacy QUIC's existing TLS1.3, packet ciphers, historical named/typed camouflage, stream lifecycle, four-second handshake bound, disabled GSO and disabled path-MTU discovery are unchanged unless explicitly listed below.

URI/JSON-node connection parameter: quicParams (aliases quicparams, quic-params, quic_params). Supported fields are maxIdleTimeout (4-120 sec), keepAlivePeriod (2-60 sec and shorter than effective idle; original default idle=60), maxIncomingStreams (8-128), and matched initial/max receive-window pairs for stream and connection (each 16384..16777216 bytes, initial <= max). A VMess Base64-JSON share envelope may carry the same nested quicParams object. Existing Full JSON finalmask.quicParams may opt in to the same approved subset on legacy QUIC. Fields absent or explicitly zero preserve existing defaults; no other transports are affected.

The importer rejects unknown, duplicated/case-ambiguous, oversized, malformed, potentially untrusted nested object fields and invalid ranges. Runtime checks the same numeric bounds. Existing QUIC TLS and packet cipher validation is retained. Explicit browser/uTLS fingerprints and custom BBR/Brutal congestion modes are NOT implemented. No silent substitution of Chrome fingerprint with stdlib TLS, weaker certificate validation, or cipher fallback. QUIC is not HTTP/3 and is not a fifth remote VPN protocol.

## Three review levels

1. Source/code structure: confined to one parser branch and an opt-in legacy QUIC tuning adapter, with unchanged default quicConfig() and non-QUIC transport code. Source review completed; full Go1.27.1 build/test is NOT_VERIFIED.
2. Compatibility: new tests authored for four-protocol URI-vs-full-config selection, VMess JSON envelope, URI-vs-JSON-node agreement, default configuration identity, safe tuning mapping and negative/unsafe combinations. Tests have NOT been run in the complete Xray module; no runtime compatibility claim is made.
3. Final gate per owner: deferred full affected/whole core Go1.27.1 suite on Windows/Linux/macOS, -race/vet/build and independent QUIC client/server wire fixtures, combined with all staged TCP/mKCP, XHTTP and Shadowsocks plugin changes. NOT_VERIFIED.

No production deployment, no changes to owner's feature/xray-custom-core branch, no app modification. Do not merge pending full-level testing and independent wire verification.
