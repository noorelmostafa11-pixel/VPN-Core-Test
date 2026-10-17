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
with `legacySettings.version: "4"`/`"4a"` implement TCP CONNECT. The old top-level
version field remains ignored on `socks`, preserving SOCKS5. SOCKS4 resolves domain
targets locally to IPv4 under the handshake deadline; SOCKS4a forwards domains
to the proxy without a local lookup. User IDs are supported, not password
authentication. IPv6 destinations, UDP and BIND are not represented as supported.
SOCKS5 remains the default and its existing TCP/UDP behavior is unchanged.
See [scope and verification](VERIFICATION-SOCKS4.md).

## VMess body compatibility with modern AEAD headers

Explicit `legacySettings.security` values `aes-128-cfb`, `none` and `zero` select
the added body semantics. Without that opt-in, original security fallbacks stay
AUTO, including unknown names. CFB uses continuous AES-CFB and the historical FNV
checksum framing; none uses unencrypted chunks; zero is unframed NONE for TCP
only, never wire security code6. Outbound defaults remain modern AEAD modes.
Inbound weak body modes require per-user `legacySettings.allowLegacyBody: true`; default
inbounds still reject them. [Body checkpoint](VERIFICATION-VMESS-BODY.md).

## Explicit legacy VMess headers

`legacySettings.alterId: 1..64` restores timestamp/HMAC-MD5 request headers, the exact
derived-ID chain, primary-ID command key, timestamp-derived CFB IV and MD5
response keys. Response CFB body state continues after the encrypted header;
AEAD and NONE bodies do not use that CFB stream. With no legacySettings, the
original modern path is retained even if an ignored top-level alterId is present.
Positive inbound legacySettings.alterId permits legacy headers for that user;
it does not permit weak bodies without legacySettings.allowLegacyBody: true.

The inbound has at most 256 legacy identities (primary plus alter IDs), a lazy
10-second lookup index with strict +/-120-second acceptance, and an 8192-entry
fail-closed replay cache. Replay identity includes primary user, body key and
IV, so legitimate same-second connections are not mistaken for replays.
These bounds deliberately do not promise unbounded historical configurations.
[Verification and acceptance boundaries](VERIFICATION-VMESS-LEGACY-HEADER.md).

The original-behavior regression fixture is run unchanged on pinned upstream
and the fork. [Isolation rules, migration and checks](VERIFICATION-PRESERVATION.md).

## Restored standalone HTTP/2 and h2c

Explicit `http`, `h2`, `http2` and `h2c` selectors register the separate `http`
transport. HTTP/2 carries the unmodified proxy bytes in a full-duplex PUT (or
explicit configured body-capable method), without gRPC/XHTTP framing or padding.
TLS uses existing certificate verification and fingerprints, requiring negotiated
`h2`; cleartext uses the HTTP/2 client preface, not HTTP/1.1 Upgrade.
`httpSettings` supports hosts, path/query, method, multi-value headers and the
historical read-idle/health-check fields. The schema retains its old field IDs.

Both endpoint roles passed local independent HTTP/2 peers, including server-first
and exact120003-byte streams. A configured VLESS core-to-core h2c case passes too.
These are not independent main/private-node or foreign-platform acceptance.
Host/method/path matching is exact (not the old upstream prefix-path listener),
reserved transport headers are rejected, and no global client pool is introduced.
HTTP/2 + REALITY is now an additional pairing, not changed to TLS or cleartext.
Pinned REALITY's authenticated empty ALPN uses an explicit H2 preface; ordinary
TLS still requires negotiated `h2`. [Pairing checks](VERIFICATION-HTTP2-REALITY.md).
The broad TLS suite still fails its unchanged external ECH test; offline checks
pass, not the whole TLS suite. [Full evidence and limits](VERIFICATION-HTTP2.md).

## Already present upstream

Do not reimplement VLESS/REALITY/Vision, modern VMess, Trojan, Shadowsocks AEAD
and 2022, WireGuard, Hysteria 2, TUN, XHTTP, WebSocket, HTTP Upgrade, gRPC or
mKCP merely because they were present in main. Upstream versions, platform
support and exact settings still require compatibility checks where used.

## Automatic node input

URI syntax, the versioned JSON node description and the Go description API now
share `conf.ResolveNode`. It identifies the required implemented capabilities,
emits their matching internal selectors, and validates the ordinary Xray
outbound/stream configuration. It neither runs a second engine nor retries a
failed connection with another protocol. Original full JSON/protobuf keeps its
meaning. The earlier node-reader contract, including classic Shadowsocks
server-first handling, is retained. This is not complete main URI/SDK parity.
[Architecture, inventory and current checks](VERIFICATION-IN-PATH-ADDONS.md);
[earlier URI coverage](VERIFICATION-NODE-SELECTION.md).

Hysteria2 now joins this shared input path using the existing upstream protocol
and transport. Both URI names, structured descriptions and Go input preserve
opaque/userpass authentication, TLS SNI/certificate pins and Salamander.
This is an input adapter, not a new Hysteria implementation or Hysteria1 alias.
[Coverage and rejected variants](VERIFICATION-NODE-HYSTERIA2.md).

## SSH TCP forwarding

An added `ssh` inbound/outbound handler runs inside the existing core lifecycle.
Password and explicit private-key/authorized-key files are supported; outbound
host-key SHA256 pins are mandatory. URI, versioned node JSON and Go input share
automatic selection for password/pin nodes. Server channels use Xray routing,
not a separate target dialer or SSH executable. Known-hosts trust, private-key
node imports, shell/exec, remote forwarding and UDP are outside this batch.
[Settings, bounds, local endpoint tests and remaining gaps](VERIFICATION-SSH.md).

## Still to port or resolve

- SS2022 fork/main interoperability requires a separate key/configuration-aware
  fixture. The existing upstream package race suite passes; that is not proof
  of compatibility with main, private nodes or every application setting.
- Standalone legacy QUIC is implemented as a separate carrier, not an XHTTP/H3
  alias. Its seven historical protobuf packet-header types are also supported;
  browser/uTLS fingerprints and advanced modern tuning remain pending. Unknown
  variants are rejected, not substituted.
  [Transport scope](VERIFICATION-LEGACY-QUIC.md) and
  [protobuf scope](VERIFICATION-QUIC-TYPED-HEADERS.md).
- Hysteria 1, TUIC v5, AnyTLS and ShadowTLS v2/v3 proxy endpoints absent from
  the pinned upstream proxy registrations.
- SSH known-hosts trust and private-key node import remain pending; current SSH
  client support requires an explicit SHA256 host-key pin. No general SSH
  application/agent, command execution or remote forwarding is promised.
- SIP003 wrapper/plugin semantics and custom health/body validation need a
  deeper comparison before declaring what upstream lacks.
- Remaining application configuration/subscription import and SDK interfaces
  need Go-first integration. The common URI reader is implemented; it does not
  alone preserve the old application ABI or cover every main link variant.

Future work should port one bounded capability at a time, retain upstream
security defaults and verify both roles where applicable. Do not import the
old engine wholesale, add a fallback executable or remove existing protocols
for a smaller language chart or executable.
