# Chrome QUIC native opt-in (full browser uTLS remains NOT_VERIFIED)

Parent: 7565d4908de4828df36393228936b59c7c27d6eb

Apernet/quic-go already has a real ChromeParrot QUIC option, used with zero-length Connection IDs in XHTTP/HTTP3. The standalone Legacy QUIC **client** now selects those options only for an explicit TLS fingerprint `chrome`. The server transport remains unmodified and QUIC configurations without the explicit field preserve their original ClientHello/TLS verification settings, packet camouflage, default CIDs, timeout and congestion. Other browser names still reject rather than silently downgrade.

Because the TLS engine in the standalone carrier remains crypto/tls, this is native QUIC Chrome transport-profile support, NOT proven byte-for-byte Chrome/uTLS ClientHello impersonation. Independent wire captures against a pinned Chrome reference are required before claiming full browser fingerprint equivalence. Full Go1.27.1 build, race, Windows/macOS and independent wire testing NOT_VERIFIED.
