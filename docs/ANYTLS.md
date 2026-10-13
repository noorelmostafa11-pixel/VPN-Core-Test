# AnyTLS and UDP-over-TCP

This is a project-authored implementation of the published AnyTLS framing,
authentication, padding and session protocol. No GPL AnyTLS/sing-box library
is imported into the runtime. The official 0.0.13 binaries are separate local
test references only (commit `9666872946857b50a74fdb692896d77b53773cb2`;
Windows amd64 ZIP SHA256
`d64996e745ac00f4bba0058163777e5dc70bc38224d836ae445ca493a2fb6c77`).

Client example:

```ini
node_uri=anytls://test-password@peer.example:443?sni=peer.example&fp=chrome
listen_port=1080
```

Standard TLS verification remains mandatory. `insecure` does not disable
verification. Existing CA settings, `pinsha256`/`pcs`, `vcn`, native/uTLS
fingerprints and configured ECH use the existing TLS component. Unknown
AnyTLS options are rejected. Authentication is SHA256 of the URI credential;
percent-encoded credentials and `username:password` are preserved.

Server example:

```json
{
  "outbounds": [{"tag": "direct", "uri": "direct://"}],
  "final": "direct",
  "inbounds": [{"protocol": "anytls", "listen": "127.0.0.1:8443",
    "password": "test-password", "cert_file": "cert.pem", "key_file": "key.pem"}]
}
```

Run with `--config server.json --no-socks`. `options.padding-scheme` optionally
sets a validated scheme. Schemes are limited to 8 KiB, 64 packet definitions,
16 segments per packet, 16 KiB per segment and 64 KiB total padded packet
work. Updates are scoped to the client/peer and apply to new sessions. MD5
is used only as the protocol's padding metadata identifier, never as an
authentication or integrity guarantee. Authentication and TLS verification
are separate. Version 2 exchanges server settings and stream acceptance;
version 1 retains its original lack of a remote-dial acknowledgement.

Clients reuse the newest idle authenticated session, with monotonically
increasing stream IDs. At most 128 active/connecting sessions per client;
the shared engine flow limit and 64-entry protocol cache also apply. A lazy
reaper retires sessions idle for 30–45 seconds. No session/reaper starts when
AnyTLS is unused. TLS server admission is capped at 64 sessions per listener;
each accepted stream uses the shared engine budget.

Frames are bounded to 65535 bytes. Each stream buffers at most 128 KiB / eight
frames and applies TCP backpressure when full, instead of dropping a valid
large payload. Deadline changes wake blocked reads; close releases buffered
data and joins owned readers/reapers/relay workers. TCP FIN is the protocol's
whole-stream close, not a half-close. No application-level replay occurs.

UDP uses the published UDP-over-TCP version 2 marker and formats. Both connect
and non-connect server modes work. Outbound UDP metadata is sent with the
initial destination before waiting for stream acceptance, matching the
reference's handshake ordering. Each server UDP association allows 16
destinations, routed/protected through the engine. The protocol's port-zero
marker is handled without allowing normal proxy destination port zero.
SOCKS/TUN/SDK paths can use TCP and these UDP streams.

Local tests cover 32 session-reuse cycles, updated padding, authentication/
trust/pin/protection/dial rejection, deadlines and owner shutdown, UDP up to
60 KiB, four non-connect destinations, v1 server reuse and 16 concurrent
bidirectional payloads of about 768 KiB each. The official standalone client
and server separately passed TCP and UDP in both directions and padding updates.
The reference client uses its documented insecure TLS example mode only for
the synthetic local server; the project's client pins the exact generated
reference certificate and its name, and never weakens its trust policy.
These are loopback results, not public-node or Windows host-network acceptance.
