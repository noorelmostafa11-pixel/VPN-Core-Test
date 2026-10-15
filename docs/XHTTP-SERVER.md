# Native XHTTP stream-one/stream-up/packet-up server carrier

Version 0.5.20-go supports XHTTP `stream-one`, `stream-up`, `packet-up` and
explicit `auto` on VLESS, VMess, Trojan and Shadowsocks TCP listeners.
Native Go HTTP handles HTTP/1.1, HTTP/2 and cleartext
prior-knowledge HTTP/2 on the configured listener. Accepted sockets and logical
streams consume the shared engine budget; handlers are registered with the
owner and execute protocols directly. Optional split sessions allocate their
state only on first use and release it with their download/setup lifetime.

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
      "mode": "auto",
      "path": "/vpn",
      "host": "your-server.example",
      "http_version": "auto"
    }
  }]
}
```

The project client uses `type=xhttp&mode=packet-up` (or another allowed mode)
with the same path/host. Omitted server mode preserves the `stream-one` default.
Advanced metadata/padding options and HTTP3 remain separate work; three-mode
wire compatibility does not imply all reference listener options.

`http_version` defaults to `auto`, advertising `h2` and `http/1.1` with TLS and
accepting both cleartext HTTP versions. `h1` or `h2` explicitly restricts the
listener and TLS ALPN. The reference fixtures match HTTP request framing to
the selected listener protocol; negotiating h2 and then sending HTTP/1.1 bytes
is rejected by the native server. TLS remains optional except on Trojan.
REALITY and pure Vision combinations remain rejected; hybrid encrypted Vision
keeps parent HTTP/TLS framing at its AEAD direct transition.

The `mode` accepts `stream-one` (the preserved default), `stream-up`,
`packet-up`, or explicit `auto`. Auto accepts all three; stream-up also accepts
a sessionless stream-one request, matching the pinned reference's listener.
Stream-one sends both directions in one request. Split modes use a GET for
download plus one streaming upload or numbered packet uploads. Standard path
metadata is supported here; custom header/query/cookie metadata and payload
placements remain separate work.

Path is bounded to 2,048 bytes and normalized with a trailing `/`. The exact
base path is used by stream-one. Split paths append an unreserved session ID
of 1–128 ASCII characters and an optional unsigned decimal sequence. Unknown
segments, duplicate/ambiguous default metadata markers, wrong modes/methods,
hosts and encodings are rejected before protocol forwarding. Host retains the
shared 253-byte hostname/port policy. Uplink method defaults to POST; another
bounded body-carrying token can be configured. Download GETs must have no body.
Forwarding headers do not override source socket metadata. WS early data,
gRPC service and HTTP-version settings on other carriers remain rejected.

Split sessions share the engine's admission budget in addition to accepted
physical sockets and active request handlers. There is one setup watcher per
pending session, exiting when its GET attaches or expiring at ConnectTimeout;
there is no listener maintenance loop or idle session pool. The download owns
the established session, and its cancellation closes the upload, queued data
and protected forwarding. Duplicate downloads/uploads, mixed upload kinds,
duplicate/stale packets and sequences outside the next 30 positions fail.
Ordered packets are reassembled before protocol authentication reads them.

Each packet body is at most 1 MiB, with at most 30 buffered posts. Actual
backing allocations (including a consumed prefix) stay charged until fully
released: at most 2*(1 MiB+1) per session and 8*(1 MiB+1) per listener, including
POST bodies still being read. Reservations precede allocation, and failed POSTs
refund their reservation. Overload is explicit (503); conflicts return 409 and
oversized bodies 413. Stream-up uses the existing bounded HTTP receive windows
without allocating a packet queue. Its finite-body EOF half-closes upload
while preserving final download response drain. Upload controllers are used
only while their native HTTP handler is running.

HTTP/1.1 explicitly enables full duplex before flushing acceptance. The raw
request body carries protocol bytes, even if the client uses an
`application/grpc` camouflage header; it is not gRPC protobuf framing.
Authentication still precedes protected upstream forwarding. Responses use
no-store, identity encoding, SSE/no-buffering headers and bounded compatibility
padding. Compression is not enabled. Headers are bounded to 8 KiB, HTTP/2 frames
to 16 KiB, HPACK tables to 4 KiB, and receive windows to 1 MiB per parent/64 KiB
per stream. Header/setup deadlines and active owner/idle cancellation remain
bounded. Advanced request-padding validation, response/header templates,
metadata placements, periodic stream-up response padding, browser CORS and HTTP/3
remain pending.

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

Split-mode native and independent results are recorded in the capability
register; configuration acceptance does not imply all upstream options.

Only final full builds are delegated to the workflow. These are local protocol
results; varied public-node Internet and live host route/DNS acceptance remain
separate.

Primary sources:
[pinned XHTTP listener](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/splithttp/hub.go),
[pinned XHTTP configuration](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/splithttp/config.go).
