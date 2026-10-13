# Hysteria 2 integration

Hysteria 2 clients and servers are embedded in the Go process. No Hysteria
executable is required at runtime. The protocol implementation is the MIT
licensed official `github.com/apernet/hysteria/core/v2` and `extras/v2`, pinned
to 2.13.0 / commit `ca8fbd874fd6ca82413948de6dc5924405e103e1`. Its authors
retain ownership. This addition does not imply Hysteria 1 support.

Client example (synthetic credentials):

```ini
node_uri=hy2://test-password@server.example:443?sni=server.example&obfs=salamander&obfs-password=test-obfs-password
listen_port=1080
```

`hysteria2://` is an alias. Authentication supports percent-encoded credentials
and `username:password`. Standard TLS trust is mandatory; `insecure` is retained
as informational input and never disables certificate verification. Explicit
`pinsha256`, `pcs`, `vcn`, custom CA fields in the existing ini/SDK, and `ech`
use the core's validation policy. `fp=chrome` enables the component's QUIC
Chrome preset; native TLS is the default. Other presets are rejected.

Optional `congestion=bbr` (default) or `reno`; `upmbps` and `downmbps` are integer
Mbps limits (1–100000), allowing the protocol's negotiated Brutal controller.
Optional obfuscation is `none`, `salamander` or `gecko`, with a 4–4096 byte
`obfs-password`. Unknown options are rejected. Port hopping, realms, fake TCP,
ACME management and Hysteria 1 are not implemented by this integration.
UDP is inherent to the Hysteria 2 carrier; a network blocking UDP cannot use it.

Server example:

```json
{
  "outbounds": [{"tag": "direct", "uri": "direct://"}],
  "final": "direct",
  "inbounds": [{
    "protocol": "hysteria2", "listen": "127.0.0.1:8443",
    "password": "test-password", "cert_file": "cert.pem", "key_file": "key.pem",
    "options": {"congestion": "bbr"}
  }]
}
```

Run with `--config server.json --no-socks`. Bind a public IP only when remote
access is intended. Server options also accept `disable-udp`, `upmbps`,
`downmbps` and the same obfuscation options. Outbound TCP and every UDP
destination use the engine's routing, socket protection and shared flow budget.
Listeners and workers start only when explicitly requested.

Client engines lazily reuse at most 64 authenticated transports. Idle entries
retire after 30–45 seconds; active entries are never evicted to make room.
Dead transports reconnect on a subsequent attempt. Changed route tables do not
reuse transports from their previous policy. TCP stream cancellation preserves
other active streams. Clients prefer working IPv4; when both families are
available, a second handshake starts after 250 ms and the losing attempt is
canceled and joined. Certificate verification and protection failures cannot
fall back to unprotected sockets.

Server admission is bounded to at most 128 QUIC connections per listener,
bounded streams per connection and the shared engine flow limit. Each UDP
association allows at most 16 destinations; each destination consumes one
engine slot. Datagram queues, fragmentation and idle cleanup are bounded.
Engine shutdown joins component client/server/UDP/obfuscation workers before
returning. Half-close sends QUIC FIN so repeated connections release promptly.

Reviewed modifications are recorded by original/replacement SHA256 hashes in
`components/patches/manifest.json`: context-aware authentication and TCP setup,
client/server worker joins and admission limits, UDP payload capacity and
fragment bounds, QUIC FIN, Gecko cleanup joins, Chrome preset parameter update
and the uTLS handshake-cancellation drain. Patches are reapplied after vendoring
and staged into gomobile's temporary modules.

Local tests cover TCP, 1/1400/32000/60000-byte UDP payloads, authentication and
trust rejection, certificate pins, IPv4 selection, handshake and stream
timeouts, 32 connect/disconnect cycles, reconnect, active owner shutdown,
obfuscation, Chrome/reno, cache admission and concurrent close.
Independent standalone Hysteria 2.13.0 clients and servers passed TCP and UDP
payloads in both directions for none/Salamander/Gecko (six combinations).
Official binary SHA256:
`162ef8fe55dc7ec810dda662908f8e65ec36bd6da39cb87c3bd66184ab68f067`.
That official build caps UDP at 4096 bytes; the independent fixture checks
32/1400/3800-byte payloads. Larger datagrams are separately verified locally.
These are loopback tests, not public-node or Windows route/DNS acceptance.
