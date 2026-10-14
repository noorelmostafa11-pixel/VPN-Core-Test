# HTTP/2 protocol server carrier

Version 0.5.18-go adds the legacy HTTP/2 byte-stream carrier to VLESS, VMess,
Trojan and Shadowsocks TCP servers. It shares the gRPC listener machinery,
engine admission, protected routing and joined handler ownership. Raw HTTP/2
streams read directly from the request body and write/flush directly to the
response; they do not allocate protobuf buffers or add a carrier forwarding
worker. gRPC now allocates its decode buffer lazily on first use.

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
      "type": "http2",
      "path": "/vpn",
      "host": "your-server.example"
    }
  }]
}
```

Project client URIs use `type=http`, with `h2`/`http2` aliases retained.
TLS advertises `h2`; cleartext accepts the prior-knowledge HTTP/2 preface.
Trojan remains TLS-only. HTTP/1.1 Upgrade negotiation is not implemented.
The parent setup deadline clears only after the complete valid preface;
subsequent streams keep independent deadlines and parent idle policy.

Requests use PUT by default. Explicit `method` may choose another bounded HTTP
token for clients that implement it; GET/HEAD/TRACE/CONNECT and method settings
on other carriers are rejected. The existing native legacy client uses PUT;
the official V2Ray fixture also exercises POST. Path defaults to `/`, is bounded
to 2,048 bytes and matches the exact decoded path. Request query strings do not
alter credentials/configuration. Optional Host retains the shared 253-byte,
case-insensitive hostname/port policy. Prefix wildcard paths, response-header
templates and broader listener options remain pending. WS early-data and gRPC
service options are rejected rather than ignored.

Compression is not enabled; requests with non-identity or duplicate content
encoding are rejected. Responses use status 200, identity encoding, no-store
and the raw protocol stream. HTTP acceptance precedes protocol authentication.
Limits retain the shared 8 KiB header policy, 4 KiB HPACK tables, 16 KiB frames,
1 MiB parent and 64 KiB stream receive windows. Parent and stream each consume
the shared connection budget; exhausted stream admission returns HTTP 503.
Upload EOF allows response drain, and canceling one stream interrupts its
protected dial without closing a reusable parent. Source metadata comes from
the socket; untrusted forwarding headers cannot replace it.

VLESS/VMess/Trojan UDP-over-stream and MUX/XUDP retain existing policy/bounds.
Generic Shadowsocks carrier support is TCP. Optional hybrid encrypted Vision
preserves HTTP/2/TLS at direct transitions. Pure Vision and REALITY combinations
remain rejected pending independent acceptance. Native encrypted Vision passed
real inner TLS/UDP; the independent V2Ray HTTP/2 fixture covers ordinary
protocol payloads, not newer hybrid encryption.

Targeted Go race checks passed repeated TCP/large atomic UDP across four
protocols, cleartext/native TLS, 16 concurrent streams with upload half-close,
escaped paths/query handling, explicit custom method, malformed host/path/method/
encoding isolation, owner close, protection cancellation and shared admission.
The native encrypted carrier matrix also now exercises gRPC; its first attempt
used different client/server service names and failed before encryption. Correct
matching service configuration passed without a production protocol change.
Official V2Ray 4.45.2 passed four protocols, PUT/POST and repeated 200,001-byte
transfers with verified TLS. Combined results are in the capability register.

Final full builds remain with the workflow. Loopback tests do not establish
varied public-node Internet, all upstream options or live host route/DNS recovery.

Primary sources:
[pinned HTTP/2 listener](https://github.com/v2fly/v2ray-core/blob/v4.45.2/transport/internet/http/hub.go),
[pinned HTTP/2 client](https://github.com/v2fly/v2ray-core/blob/v4.45.2/transport/internet/http/dialer.go).
