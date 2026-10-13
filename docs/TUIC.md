# TUIC v5

Project-authored client and server implementing the version 5 wire protocol.
Specification revision: `8e118f242f24a17a9f487dc344cc50d7e63e557e`,
[primary specification](https://github.com/tuic-protocol/tuic/blob/8e118f242f24a17a9f487dc344cc50d7e63e557e/SPEC.md).
No other proxy engine is linked or launched. The existing pinned BSD/MIT
quic-go component provides QUIC transport and its default congestion control.

Client example:

```text
tuic://12345678-1234-4567-9234-567812345678:password@vpn.example:443?udp-relay-mode=native&alpn=h3
```

TCP uses bidirectional streams; UDP supports QUIC datagrams (`native`) and
unidirectional streams (`quic`). Fragmentation/reassembly accepts UDP payloads
through 65,507 bytes. Authentication binds the UUID/password token to the
current TLS exporter. Destination names are encoded in the relay request.
Endpoint fallback prefers working IPv4, with IPv6 available. IPv4/IPv6
addresses and domain names use the published address encoding.

Certificates are verified against configured/system roots, names and pins.
ECH uses the native TLS implementation. `sni`/`peer`, `alpn`, `pinsha256`,
`pcs`, `vcn`, and either spelling of `udp-relay-mode` are supported. Legacy
insecure flags do not disable certificate verification. QUIC 0-RTT, selectable
BBR/new-Reno and uTLS fingerprints are not implemented for TUIC in this
extension; unsupported requested options are rejected. Versions before v5 are
not accepted. TCP detours that require an unimplemented UDP carrier are rejected.

Server entry (inside a routing profile's `inbounds`):

```json
{
  "protocol": "tuic",
  "listen": "0.0.0.0:443",
  "uuids": ["12345678-1234-4567-9234-567812345678"],
  "password": "password",
  "cert_file": "server.pem",
  "key_file": "server.key",
  "options": {"alpn": "h3"}
}
```

Up to 128 UUIDs share the configured password. Per-user passwords are a
remaining configuration extension. The server shares the engine's routing,
socket protection and flow budget. Direct UDP uses an unconnected protected
socket per address family, preserving its port between destinations and
accepting Full Cone replies. Every request re-evaluates routing; changing a
destination to block cannot reuse that socket to bypass the block. Proxy UDP
destinations retain the outbound protocol's NAT behavior.

Clients are created only when first used and reused by engine/outbound/route
generation. The common cache retires idle clients after 30 seconds. Limits
include 64 connections per server listener, 64 UDP associations per QUIC
connection, 32 concurrent command readers, eight queued packets per association,
eight incomplete packets/128 KiB of fragments per association, 65,507 bytes per
assembled packet, and five-second fragment expiry. Server associations and
physical UDP sockets consume the shared flow budget. Retired association IDs
are not resurrected by late packets. Shutdown closes transports and joins all
owned workers; a stream close does not close other cached streams.

TUIC has no authentication or destination success response. Returning a QUIC
stream proves local framing and TLS setup, not that a remote destination works.
Payload verification remains necessary for connectivity/health claims.

Local tests cover 32 TCP reuse cycles, repeated UDP close, 60 KiB packets in
both modes, reordered/malformed fragments, bounded admission, 12 concurrent
large TCP flows, protection/authentication/trust rejection, endpoint timeout,
Full Cone source-port reuse, routing block replacement and owner loss.

Independent reference: official sing-box **1.14.3**, revision
`7054cac5124465ffdb145870d7c01885566711b1`; its executable is used only by
tests, not included in runtime/distribution. Official Windows archive SHA256:
`d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518`.
TCP and UDP payloads passed in both client/server directions and UDP modes.
The Windows reference fixture's direct/SOCKS UDP buffers reject large packets;
independent UDP coverage is 32/1,400/3,800 bytes. Go-to-Go 60 KiB results are
recorded separately. The first reference run with larger packets failed and
is not described as passing.

Run `test_tuic_reference.TUICReferenceTests` with
`VPN_CORE_REFERENCE_SINGBOX` pointing at the reference executable. Local
protocol results do not establish public-node or Windows OS route/DNS acceptance.
