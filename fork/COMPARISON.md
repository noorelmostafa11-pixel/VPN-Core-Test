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

The second batch restores all nine AES-CFB/CTR/OFB method names, with exact
128/192/256-bit keys and 16-byte IVs. Client and single-user server TCP/UDP are
supported. No default is changed and no algorithm is substituted. Multi-user
lists remain restricted to authenticated AEAD methods. The runtime validator
also prevents either order of mixing a legacy account with another account.

The third batch adds eleven other classic method names: `bf-cfb`, `cast5-cfb`,
`des-cfb`, `rc4`, `rc4-md5`, `salsa20`, `chacha20`, `chacha20-ietf`, `table`,
`none` and `plain`. The last two names are aliases, not separate algorithms.
Original ChaCha retains its 8-byte nonce and full 64-bit block counter; it is
not an alias for the IETF 12-byte nonce construction. Plaintext remains explicit
and all unauthenticated methods remain single-user only.

The fourth batch adds the remaining six names: `camellia-128-cfb`,
`camellia-192-cfb`, `camellia-256-cfb`, `idea-cfb`, `rc2-cfb` and `seed-cfb`.
RC2 uses 128 effective key bits; seed-cfb uses SEED-128. Four narrowly vendored
Go primitive packages, their tests, an alias helper and license/source notices
are retained; no native engine or new module dependency is imported.
All 32 classic names in pinned main's `core/protocol.go` now pass local
Windows client/server TCP/UDP interoperability. Aliases are included in this
count; the other three names are SS2022, already present upstream but not
covered by this classic wire harness. See [checks](VERIFICATION-BLOCK-CFB.md).

## SOCKS4 and SOCKS4a outbound

Explicit `socks4`/`socks4a` protocol selectors and the existing `socks` settings
with `version: "4"`/`"4a"` now implement TCP CONNECT. SOCKS4 resolves domain
targets locally to IPv4 under the handshake deadline; SOCKS4a forwards domains
to the proxy without a local lookup. User IDs are supported, not password
authentication. IPv6 destinations, UDP and BIND are not represented as supported.
SOCKS5 remains the default and its existing TCP/UDP behavior is unchanged.
See [scope and verification](VERIFICATION-SOCKS4.md).

## Already present upstream

Do not reimplement VLESS/REALITY/Vision, modern VMess, Trojan, Shadowsocks AEAD
and 2022, WireGuard, Hysteria 2, TUN, XHTTP, WebSocket, HTTP Upgrade, gRPC or
mKCP merely because they were present in main. Upstream versions, platform
support and exact settings still require compatibility checks where used.

## Still to port or resolve

- SS2022 fork/main interoperability requires a separate key/configuration-aware
  fixture. The existing upstream package race suite passes; that is not proof
  of compatibility with main, private nodes or every application setting.
- Legacy VMess alter-ID/AES-CFB and none/zero semantics. Mapping unsupported
  strings to AUTO is not implementation of the requested wire behavior.
- Legacy standalone HTTP/2/h2c and QUIC transports removed from upstream. XHTTP
  is not an interchangeable wire-level alias for these protocols.
- Hysteria 1, TUIC v5, AnyTLS, ShadowTLS v2/v3 and SSH proxy endpoints absent from
  the pinned upstream proxy registrations.
- SIP003 wrapper/plugin semantics and custom health/body validation need a
  deeper comparison before declaring what upstream lacks.
- Application configuration import and SDK interfaces need a Go-first integration
  design. The upstream CLI alone does not preserve the old application ABI.

Future work should port one bounded capability at a time, retain upstream
security defaults and verify both roles where applicable. Do not import the
old engine wholesale, add a fallback executable or remove existing protocols
for a smaller language chart or executable.
