# Hysteria 1

The project implements the Hysteria 1 binary v3 protocol in Go, independently of
the Hysteria 2 HTTP/3 authentication path. It uses the already pinned MIT QUIC
transport and Brutal controller inside this process. No other proxy engine is
launched or linked. The wire/URI references are the official
[v1 specification](https://v1.hysteria.network/docs/protocol/) and
[URI scheme](https://v1.hysteria.network/docs/uri-scheme/), with independent
acceptance against Hysteria 1.3.5 / `57c5164854d6cfe00bead730cce731da2babe406`.

## Configuration

```text
hysteria://vpn.example:443?auth=secret&upmbps=100&downmbps=100&peer=vpn.example
hysteria://vpn.example:443?auth=secret&upmbps=100&downmbps=100&obfs=xplus&obfsParam=obfs-secret
```

`hysteria1://` is an alias. An explicit port and positive integer `upmbps` and
`downmbps` are required (1–100,000 Mbps). Authentication may be empty for an
upstream server using no authentication; this project's servers always require
an explicit nonempty password. `peer`/`sni`, native TLS, `alpn` (default
`hysteria`), custom roots, pins/name checks and the existing native ECH resolver
are available. ECH configuration is not evidence of v1 public-server ECH support.
An insecure URI request never disables certificate verification. Unknown,
duplicate or unsupported carrier/fingerprint settings are rejected explicitly.

An inbound is configured independently:

```json
{
  "protocol": "hysteria",
  "listen": "0.0.0.0:443",
  "password": "secret",
  "cert_file": "server-cert.pem",
  "key_file": "server-key.pem",
  "options": {"upmbps": "100", "downmbps": "100"}
}
```

Server options also accept `alpn`, `obfs=xplus` with `obfsparam` or
`obfs-password`, and `disable-udp=true|false`. TLS 1.3 is required by QUIC.
Rates are negotiated as the lesser of each side's offered receive/send limit;
the pinned Brutal controller uses the agreed send rate. This is a configured
rate, not a measured throughput claim.

## Ownership and limits

TCP waits for authentication and a destination response before reporting setup
success. Data streams support half-close. UDP sessions hold a stream open for
their lifetime, use separate server-assigned IDs, and support multiple remote
addresses, IPv4/IPv6 and fragmentation. Direct server traffic shares one
protected unconnected UDP socket per address family within a session; replies
and each new destination are checked against current routing policy. Proxy and
block decisions retain the engine's routed path; protection errors never fall
back to direct traffic.

Connections reuse the common lazy 64-client cache. Server admission is limited
to 64 QUIC connections per listener; streams and physical outbound sockets use
the engine's shared flow budget. Each peer permits 64 UDP sessions, with an
eight-packet receive queue per session. Server-assigned IDs are monotonic and
are never reused within a connection. Unknown/closed sessions cannot be revived
by late datagrams. Idle sessions expire after 30 seconds, checked every five
seconds. Fragmentation is capped at 128 parts and 65,507 payload bytes, with
eight incomplete messages / 128 KiB / five-second expiry per session.

Owner shutdown cancels streams, UDP sockets and datagram send backpressure,
then joins owned workers. The optional pinned QUIC context-send extension
interrupts one session's blocked send without closing other flows. Fragment
transmission has the configured connection timeout and packet deadline.
Features create no Hysteria workers or sockets when unused.

## Acceptance and remaining scope

Local Go tests cover 32 TCP reuse cycles, eight UDP cycles including 60 KiB,
eight concurrent 200 KiB TCP payloads, dead-session replacement, owner loss,
certificate/pin/authentication rejection, cancelled sends, 64-session admission,
server/client protection failures, shared flow limits, UDP disable, IPv4 success
with an unavailable IPv6 path, wire/fragment bounds and malformed settings.

The independent executable passes TCP and UDP in both directions, with and
without xplus: 16 TCP cycles and eight UDP associations per combination, with
32-, 1,400- and 3,800-byte UDP payloads. Its Windows AMD64 SHA256 is
`1001bd4a83f6addac166bfdfc3e777f3b751bb397e11b5d8f1d6ec1c2dd44023`.
The official 1.3.5 server reads UDP into a 4 KiB buffer, so the independent
fixture stays below that reference limit; the larger own-engine payload test is
reported separately.

The first independent run passed TCP but failed UDP at fragmentation. Review
found that old QUIC peers decide fragmentation from the advertised DATAGRAM
frame size without the newer path-size check. Advertising 16 KiB let them queue
packets that could not fit the path. This adapter advertises a conservative
1,000-byte frame limit and sends at most 997 payload bytes per frame. The
corrected independent run passed; the initial failure is retained locally.

Port hopping, wechat-video/fake-TCP carriers, configurable uTLS fingerprints,
external authentication and multiple server passwords remain pending. These
local wire/lifecycle results do not establish varied public-node Internet
access, OS routing/DNS recovery, or all upstream option support.
