# gRPC protocol server carrier

Version 0.5.17-go adds `Tun` and `TunMulti` to VLESS, VMess, Trojan and
Shadowsocks TCP listeners. The carrier uses the already vendored HTTP/2
implementation and project protobuf framing; it adds no gRPC/protobuf runtime,
global connection pool or maintenance worker. Listener workers start only when
configured. Each HTTP/2 parent and protocol stream shares engine admission,
protected routing, owner cancellation and joined shutdown.

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
      "type": "grpc",
      "service": "vpn.service",
      "host": "your-server.example"
    }
  }]
}
```

TLS advertises `h2`; cleartext uses the HTTP/2 prior-knowledge preface. Trojan
still requires TLS. HTTP/1.1 Upgrade negotiation is not implemented here.
Both RPC methods are available on the listener: `/vpn.service/Tun` and
`/vpn.service/TunMulti`. Omitted service defaults to `GunService`, with the
existing native client's empty-service paths also accepted. A service beginning
with `/` defines custom method paths, for example
`/nested/service/Custom|CustomMulti`; without the second name, the multi method
defaults to `TunMulti`. Empty/duplicate method or intermediate segments are
rejected. Service is bounded to 256 bytes and optional Host to 253 bytes.
WS path/early-data options are rejected rather than ignored.

Requests require HTTP/2 POST, the configured path/host and an unambiguous
`application/grpc` or `application/grpc+...` content type. Compressed messages
and non-identity encoding are rejected. Header size is bounded to 8 KiB, HPACK
tables to 4 KiB, frames to 16 KiB, and receive windows to 1 MiB per parent and
64 KiB per stream. The existing protobuf decoder bounds buffered input to
1 MiB and each message to 512 KiB. Responses use 8 KiB payload chunks.
TunMulti concatenates repeated field-1 bytes in wire order; Tun uses the last
singular field value, matching protobuf semantics. Forwarding headers cannot
replace source socket metadata.

Logical streams retain independent read/write deadlines and cancellation. A
validated HTTP/2 preface clears the parent setup deadline; incomplete/wrong
prefaces retain that deadline. Protocol execution runs in the already owned
native handler, without an extra forwarding worker/completion channel. A
normal upload EOF lets the response finish and emit status 0; failed protocol
authentication/handshake emits a failed stream or reset. Capacity rejection
returns gRPC status 8. Closing a stream does not close its reusable parent;
closing the engine cancels and joins incomplete handlers and protocol workers.
HTTP transport acceptance precedes UUID/password/cipher authentication and
does not grant forwarding access.

VLESS/VMess/Trojan UDP-over-stream and VLESS/VMess MUX/XUDP retain their existing
bounds. Shadowsocks generic carrier support remains TCP. Optional VLESS hybrid
encryption and encrypted Vision operate inside the stream and retain outer
HTTP/2/TLS at direct transitions. Pure Vision and REALITY combinations remain
explicitly rejected pending independent acceptance. Wider gRPC compression,
health/reflection and trusted forwarding options are not implemented.

Targeted Go race checks passed four protocols, both methods, cleartext/native
TLS, repeated TCP and large atomic UDP, 16 concurrent transfers on one parent,
upload half-close/status, parent reuse beyond the setup deadline, malformed
request/message isolation, admission limits,
protected route rejection and incomplete owner shutdown. Official Xray 26.7.28
passed both four-protocol matrices and native/random encrypted Vision with
verified inner TLS and XUDP. Initial compilation referenced the old assertion
that gRPC was unsupported; that fixture was corrected, with its failed run
retained. Combined local results are recorded in the capability register.

Final full platform/package builds belong to the workflow. Loopback acceptance
does not establish varied public-node Internet or OS route/DNS recovery.

Primary sources:
[pinned RPC listener](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/grpc/hub.go),
[pinned protobuf schema](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/grpc/encoding/stream.proto),
[HTTP/2 library](https://pkg.go.dev/golang.org/x/net/http2).
