# Protocol server carriers

Version 0.5.16-go adds opt-in WebSocket and HTTP Upgrade to VLESS, VMess,
Trojan and Shadowsocks TCP listeners. It uses the existing Go framing code,
admitted connection workers, protected routing and joined owner shutdown.
No new WebSocket library, HTTP service pool or heartbeat worker is added.

```json
{
  "outbounds": [{"tag": "direct", "uri": "direct://"}],
  "final": "direct",
  "inbounds": [{
    "protocol": "vless",
    "listen": "127.0.0.1:4433",
    "uuids": ["<your UUID>"],
    "cert_file": "server.pem",
    "key_file": "server-key.pem",
    "transport": {
      "type": "websocket",
      "path": "/vpn",
      "host": "your-server.example",
      "early_data": 2048
    }
  }]
}
```

Use `httpupgrade` for the byte-stream upgrade carrier; omit `early_data` in
that mode. Omitted `transport` or explicit `{"type":"raw"}` retains raw TCP.
TLS is optional on VLESS/VMess/Shadowsocks and remains required on Trojan.
TLS carrier listeners advertise HTTP/1.1. REALITY with these two carriers is
explicitly rejected until reference acceptance is added. Ordinary Vision over
WS/Upgrade without hybrid encryption is also rejected; encrypted Vision is
implemented and keeps the carrier/outer TLS during AEAD direct transitions.

Path defaults to `/`, is bounded to 2,048 bytes and must be an origin-form URI.
Matching uses its decoded path; query parameters do not become credentials or
early-data settings. Optional Host is bounded to 253 bytes, case-insensitive,
and may restrict requests. A bare configured hostname also accepts a request
port suffix. Supplied forwarding/source headers do not override socket metadata.

HTTP request headers are bounded to 8 KiB. The listener requires HTTP/1.1 GET
and an Upgrade token, rejects bodies/transfer encoding and ambiguous duplicate
critical headers, and checks path/host before protocol forwarding. Unknown or
malformed requests receive a bounded HTTP error. UUID/password/cipher/flow
authentication still follows the carrier handshake; HTTP acceptance does not
grant upstream access. All bytes prefetched after headers are preserved.

WebSocket requires version 13 and a 16-byte key, masked client frames and
unmasked server frames. Binary and continuation frames support streaming
fragmentation; ping/pong/close retain their framing limits. Extension/compression
negotiation and text messages are rejected. Each frame is bounded to 512 KiB;
control frames to 125 bytes, 32 controls and 64 no-progress frames per Read.
This prevents unbounded empty/control loops without a maintenance timer.
WebSocket close is a protocol close, not independent TCP half-close.

Early data is disabled by default and bounded to 4,096 decoded bytes when
configured. The default header is `Sec-WebSocket-Protocol`; an explicit valid
non-reserved `early_header` is also supported for project clients. Base64url/
standard base64 forms are checked before decoding. The accepted subprotocol
value is echoed when that header carries data. Decoded bytes precede subsequent
WebSocket data without dropping buffered frames. HTTP Upgrade does not accept
these early-data options.

VLESS/VMess/Trojan UDP-over-stream and MUX/XUDP retain their existing policy and
packet limits. Shadowsocks carrier support is TCP; its native UDP listener
remains separately configured by `options.udp`, and can be disabled with
`"false"`. SS2022 and the existing TCP cipher implementation remain available;
these carrier fixtures use AEAD2017. SS UOT over these generic listeners is
still work and must not be inferred from ShadowTLS's separate UOT support.

Targeted Go race checks passed repeated TCP across four protocols/two carriers,
verified native TLS, large atomic UDP for VLESS/VMess/Trojan, explicit WS early
data and escaped paths, coalesced headers/data, masked fragmented/control frames,
malformed configuration/headers/frames, limits and incomplete owner shutdown.
Encrypted native/random Vision passed actual inner TLS and UDP through both
carriers; TLS metadata now unwraps SDK/encryption layers correctly.
Official Xray 26.7.28 passed four-protocol carrier payloads and encrypted Vision
with plain/inner TLS and XUDP. The original Trojan reference first-body check
hit Xray's fixed buffer before sending a protocol header; a small authenticated
first exchange now precedes the unchanged 200,001-byte test and timeout. Initial
fixture credential and metadata failures are retained separately from passes.
Combined race/wire results are recorded in the capability register.

Version 0.5.17 adds gRPC Tun/TunMulti; see [GRPC-SERVER.md](GRPC-SERVER.md).
Version 0.5.18 adds HTTP2/h2c; see [HTTP2-SERVER.md](HTTP2-SERVER.md).
Version 0.5.19 adds XHTTP stream-one over HTTP1/HTTP2/h2c;
see [XHTTP-SERVER.md](XHTTP-SERVER.md).
XHTTP stream-up/packet-up, QUIC/HTTP3/mKCP server carriers, PROXY/trusted forwarding,
compression and wider HTTP listener options remain pending. Mobile/C ABI server
startup remains pending. Final full builds belong to the workflow; local
payload/race checks do not establish varied public-node Internet or host OS
route/DNS recovery.

Primary sources:
[WebSocket wire format](https://www.rfc-editor.org/rfc/rfc6455.html),
[pinned WS reference](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/websocket/hub.go),
[pinned Upgrade reference](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/httpupgrade/hub.go),
[Trojan first exchange](https://github.com/XTLS/Xray-core/blob/v26.7.28/proxy/trojan/client.go).
