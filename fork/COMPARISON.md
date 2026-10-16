# Pinned-source comparison backlog

Reference commits and versions are in [manifest.json](manifest.json). This is a
source audit, not proof that every private node works or that all main features
have been migrated. Native-core development after the pinned main is not the
comparison reference.

## First port

Shadowsocks AES-192-GCM was missing from the pinned upstream. It is added here
without changing existing cipher enum numbers or default method selection.
Its 24-byte key must be truncated from the full MD5 derivation block output;
otherwise an accidental 32-byte AES-256 implementation would be wire-incompatible.

## Already present upstream

Do not reimplement VLESS/REALITY/Vision, modern VMess, Trojan, Shadowsocks AEAD
and 2022, WireGuard, Hysteria 2, TUN, XHTTP, WebSocket, HTTP Upgrade, gRPC or
mKCP merely because they were present in main. Upstream versions, platform
support and exact settings still require compatibility checks where used.

## Still to port or resolve

- Remaining historical Shadowsocks methods/aliases in main. The 35 method names
  in main are not 35 distinct algorithms. Legacy cipher security policy must be
  explicit; do not silently replace a requested cipher with another method.
- Legacy VMess alter-ID/AES-CFB and none/zero semantics. Mapping unsupported
  strings to AUTO is not implementation of the requested wire behavior.
- Legacy standalone HTTP/2/h2c and QUIC transports removed from upstream. XHTTP
  is not an interchangeable wire-level alias for these protocols.
- Hysteria 1, TUIC v5, AnyTLS, ShadowTLS v2/v3 and SSH proxy endpoints absent from
  the pinned upstream proxy registrations.
- SOCKS4/4a outbound compatibility; distinguish it from existing SOCKS5 and
  inbound version support.
- SIP003 wrapper/plugin semantics and custom health/body validation need a
  deeper comparison before declaring what upstream lacks.
- Application configuration import and SDK interfaces need a Go-first integration
  design. The upstream CLI alone does not preserve the old application ABI.

Future work should port one bounded capability at a time, retain upstream
security defaults and verify both roles where applicable. Do not import the
old engine wholesale, add a fallback executable or remove existing protocols
for a smaller language chart or executable.
