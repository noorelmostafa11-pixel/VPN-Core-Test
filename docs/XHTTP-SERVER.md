# Native XHTTP stream-one server carrier

Version 0.5.19-go adds explicit XHTTP `stream-one` to VLESS, VMess, Trojan and
Shadowsocks TCP listeners. Native Go HTTP handles HTTP/1.1, HTTP/2 and cleartext
prior-knowledge HTTP/2 on the configured listener. Accepted sockets and logical
streams consume the shared engine budget; handlers are registered with the
owner and execute protocols directly. No carrier forwarding worker, global
HTTP pool, session cache or maintenance timer is added.

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
      "type": "xhttp",
      "mode": "stream-one",
      "path": "/vpn",
      "host": "your-server.example",
      "http_version": "auto"
    }
  }]
}
```

The project client uses `type=xhttp&mode=stream-one` with the same path/host.
Omitted server mode currently defaults to `stream-one`. `packet-up`, `stream-up`
and `auto` are explicitly rejected until their bounded shared-session server
implementation is delivered; client implementations of those modes remain
available. This revision must not be advertised as complete XHTTP server support.

`http_version` defaults to `auto`, advertising `h2` and `http/1.1` with TLS and
accepting both cleartext HTTP versions. `h1` or `h2` explicitly restricts the
listener and TLS ALPN. The reference fixtures match HTTP request framing to
the selected listener protocol; negotiating h2 and then sending HTTP/1.1 bytes
is rejected by the native server. TLS remains optional except on Trojan.
REALITY and pure Vision combinations remain rejected; hybrid encrypted Vision
keeps parent HTTP/TLS framing at its AEAD direct transition.

Path is bounded to 2,048 bytes, normalized with a trailing `/`, and matches its
exact decoded path. Optional Host retains the shared 253-byte hostname/port
policy. Request query/padding and user-supplied forwarding headers do not alter
credentials or source socket metadata. Default session/sequence query/header
markers and extra path segments are rejected in this stream-one listener.
Method defaults to POST; another bounded body-carrying token can be configured.
GET/HEAD/TRACE/CONNECT/OPTIONS, WS early data, gRPC service and HTTP-version
settings on other carriers are rejected rather than ignored.

HTTP/1.1 explicitly enables full duplex before flushing acceptance. The raw
request body carries protocol bytes, even if the client uses an
`application/grpc` camouflage header; it is not gRPC protobuf framing.
Authentication still precedes protected upstream forwarding. Responses use
no-store, identity encoding, SSE/no-buffering headers and bounded compatibility
padding. Compression is not enabled. Headers are bounded to 8 KiB, HTTP/2 frames
to 16 KiB, HPACK tables to 4 KiB, and receive windows to 1 MiB per parent/64 KiB
per stream. Header/setup deadlines and active owner/idle cancellation remain
bounded. Advanced request-padding validation, response/header templates,
metadata placements, browser CORS and HTTP/3 remain pending.

Normal request-body EOF retains response drain and parent reuse. Closing an
incomplete body interrupts its read deadline; a body that already reached EOF
does not receive an artificial read timeout that could cancel HTTP/1.1's final
response flush. Per-stream cancellation interrupts protected dialing. Engine
close joins protocol handlers, closes admitted sockets and preserves zero
active admission. VLESS/VMess/Trojan UDP-over-stream and MUX/XUDP retain bounds;
Shadowsocks generic XHTTP is TCP, with separately configured native UDP retained
through the existing bounded dual-bind/rollback path.

Go race checks passed repeated TCP/atomic UDP, native TLS, encrypted Vision with
verified inner TLS/metadata, HTTP/1.1 finite-body half-close/reuse, malformed
method/path/host/encoding/session rejection, protection cancellation, incomplete
owner shutdown, direct cleartext HTTP/2 payload and native Shadowsocks UDP.
The first finite-body test exposed an artificial EOF read deadline canceling
response drain; EOF tracking corrected it without relaxing body/time limits.
Initial reference fixtures included a reference-only ALPN field in strict
project configuration, then mismatched HTTP/1.1 framing and negotiated h2.
The corrected listener/framing settings passed unchanged payload/deadline checks.
Official Xray 26.7.28 passed four protocols over cleartext/verified TLS,
HTTP/1.1/HTTP/2, plus native/random encryption with Vision/inner TLS/XUDP.
Failures and combined local results are retained in the capability register.

Only final full builds are delegated to the workflow. These are local protocol
results; varied public-node Internet and live host route/DNS acceptance remain
separate.

Primary sources:
[pinned XHTTP listener](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/splithttp/hub.go),
[pinned XHTTP configuration](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/splithttp/config.go).
