# Native XHTTP stream-one/stream-up/packet-up server carrier

Version 0.5.24-go supports XHTTP `stream-one`, `stream-up`, `packet-up` and
explicit `auto` on VLESS, VMess, Trojan and Shadowsocks TCP listeners.
Native Go HTTP handles HTTP/1.1, HTTP/2 and cleartext prior-knowledge HTTP/2;
explicit `http_version: "h3"` selects a TLS 1.3 QUIC/HTTP3 UDP listener.
Accepted connections and logical
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
Periodic padding, arbitrary response templates and CORS remain separate work; three-mode
wire compatibility does not imply all reference listener options.

`http_version` defaults to `auto`, advertising `h2` and `http/1.1` with TLS and
accepting both cleartext HTTP versions. `h1` or `h2` explicitly restricts the
listener and TLS ALPN. `h3` requires a certificate/key and advertises only `h3`;
`auto` retains the existing TCP HTTP1/HTTP2 listener and does not open UDP.
The reference fixtures match HTTP request framing to
the selected listener protocol; negotiating h2 and then sending HTTP/1.1 bytes
is rejected by the native server. TLS remains optional except on Trojan and h3.
REALITY and pure Vision combinations remain rejected; hybrid encrypted Vision
keeps parent HTTP/TLS framing at its AEAD direct transition.

The `mode` accepts `stream-one` (the preserved default), `stream-up`,
`packet-up`, or explicit `auto`. Auto accepts all three; stream-up also accepts
a sessionless stream-one request, matching the pinned reference's listener.
Stream-one sends both directions in one request. Split modes use a GET for
download plus one streaming upload or numbered packet uploads. Standard path
metadata remains the default. Version 0.5.22 also supports independently selected
path/query/header/cookie locations for session IDs and packet sequences, with
optional custom key names. Version 0.5.23 also supports body/header/cookie/auto
packet payload placement, independently of session/sequence metadata.

For example, both endpoints can use these XHTTP options (nested under the
server's `transport.extra` or the client's XHTTP extra):

```json
{
  "sessionIDPlacement": "header",
  "sessionIDKey": "Meta-Session",
  "seqPlacement": "query",
  "seqKey": "meta_seq"
}
```

These four fields, `uplinkDataPlacement`/`uplinkDataKey`, the six `xPadding*`
fields below and `noSSEHeader` are currently accepted in server `extra`; the
strict profile decoder rejects unimplemented options. Metadata keys default to `X-Session` and
`X-Seq` for headers, or `x_session` and `x_seq` for query/cookie. Path locations
take no key. Header names compare without case; query/cookie keys retain case.
Names are HTTP tokens of at most 128 bytes; framing/encoding/cookie header keys,
colliding session/sequence keys in the same location and metadata names in the
configured payload chunk namespaces are rejected at setup.
Compiled options copy their configuration rather than aliasing mutable input.

The base path gains a trailing slash when either field uses path metadata;
otherwise the configured base path is matched exactly. Path fields are appended
in session-then-sequence order. Missing session/sequence on the base path still
selects sessionless stream-one when the listener mode allows it. Empty/repeated
metadata, malformed queries, stray path segments and conflicting configured or
default metadata in other locations fail before session allocation/admission.

Path is bounded to 2,048 bytes, with trailing `/` normalization as described above. The exact
base path is used by stream-one. Split requests carry an unreserved session ID
of 1–128 ASCII characters and an optional unsigned decimal sequence. Unknown
segments, duplicate/ambiguous default metadata markers, wrong modes/methods,
hosts and encodings are rejected before protocol forwarding. Host retains the
shared 253-byte hostname/port policy. Uplink method defaults to POST; another
bounded body-carrying token can be configured. Explicit GET uploads require
header/cookie packet placement and a sequence; GET without a sequence remains
the download and must have no body. Non-body packet placements require
`packet-up` or explicit `auto` mode, not stream-one/stream-up.
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

`uplinkDataPlacement` defaults to `body`. `header` uses `uplinkDataKey-N`
fields (default key `X-Data`); `cookie` uses `uplinkDataKey_N` cookies (default
key `x_data`). Chunk indices start at zero, are canonical decimal, contiguous
and unique, with at most 128 chunks per carrier. Chunks concatenate in numeric
order before strict unpadded Base64URL decoding. Empty chunks, invalid alphabet,
noncanonical trailing bits, duplicates/gaps and more than 8 KiB combined encoded
header/cookie payload fail before session creation. Existing complete HTTP
header limits also apply and generally bound the usable payload below that.
`auto` uses the default key `x_data` and concatenates decoded header, decoded
cookie and raw body, in that order. Body-only rejects configured payload chunks;
header/cookie-only reject the other carrier and require an actually empty body,
including unknown-length HTTP3 FIN. Client carrier/key settings must agree with
the server; server `auto` accepts any of the three carriers with its configured
key, while the client maps its own `auto` placement to body.

Each combined decoded packet is at most 1 MiB, with at most 30 buffered posts.
Actual backing allocations (including a consumed prefix) stay charged until fully
released: at most 2*(1 MiB+1) queued per session and 8*(1 MiB+1) per listener,
including uploads still being read. Decoded backing plus encoded scratch are
reserved before allocation; scratch is refunded after decoding, and the retained decoded
capacity is charged until consumed. Failed uploads refund their reservation.
Overload is explicit (503); conflicts return 409 and oversized packets 413.
The client also budgets the uncompressed HTTP2/HTTP3 field-list overhead and
splits an oversized header/cookie packet before any network I/O, without
replaying sent data or increasing header limits.
Stream-up uses the existing bounded HTTP receive windows
without allocating a packet queue. Its finite-body EOF half-closes upload
while preserving final download response drain. Upload controllers are used
only while their native HTTP handler is running.

Version 0.5.24 adds explicit request-padding policy and bounded response padding:

```json
{
  "xPaddingBytes": "64-96",
  "xPaddingObfsMode": true,
  "xPaddingPlacement": "header",
  "xPaddingHeader": "Pad-Header",
  "xPaddingKey": "pad_key",
  "xPaddingMethod": "tokenish",
  "noSSEHeader": true
}
```

Setting `xPaddingBytes`, enabling `xPaddingObfsMode`, or providing a nonempty
padding key/header/placement/method enables required request validation.
`noSSEHeader` alone does not. With no padding options, existing request behavior and the
100-byte `X-Padding` response are retained, including previously configured
metadata names. `xPaddingBytes` accepts a number or inclusive `"min-max"` range;
Go callers use `XHTTPPaddingRange{From: 64, To: 96}`. Explicit server targets
are 1–4,096 bytes, leaving room inside the existing 8 KiB header budget for
tokenish expansion, keys and fixed response fields. The default target range
when padding is enabled is 100–1,000. Compiled range values copy caller state.

`repeat-x` validates raw byte length; it does not require every byte to be X.
`tokenish` validates HPACK Huffman byte length with the reference's two-byte
tolerance, not the raw string length. Validation is bounded to 8 KiB of raw
padding. Empty, repeated, conflicting-carrier, out-of-range, malformed URL/query
and CR/LF/NUL values fail with 400 before allocating a split session or
forwarding protocol bytes. Padding/header keys are bounded HTTP tokens; framing
header names and metadata/payload namespace collisions fail during setup.

With `xPaddingObfsMode: true`, requests must use the selected placement:
`header` reads `xPaddingHeader`; `query` and `cookie` read `xPaddingKey`;
`queryInHeader` reads that key from the URL in `xPaddingHeader`. Defaults are
`queryInHeader`, `X-Padding`, `x_padding` and `repeat-x`. Responses use the same
header, URL-query-in-header or cookie carrier (cookies have Path=/). Query mode
adds no response padding because a response has no URL query. With obfuscation
off, requests retain legacy `Referer` URL/`x_padding` handling, falling back to
the direct query only when Referer is absent; responses use repeat-X `X-Padding`.
Configured placement/key overrides require obfuscation mode to take effect.
The selected placement is authoritative rather than silently falling back to
another carrier. Generation/validation runs in existing request handlers; no
padding worker, pool, maintenance timer or listener is added.

HTTP/1.1 explicitly enables full duplex before flushing acceptance. The raw
request body carries protocol bytes, even if the client uses an
`application/grpc` camouflage header; it is not gRPC protobuf framing.
Authentication still precedes protected upstream forwarding. Responses use
no-store, identity encoding, SSE/no-buffering headers and bounded compatibility
padding. Compression is not enabled. Headers are bounded to 8 KiB, HTTP/2 frames
to 16 KiB, HPACK tables to 4 KiB, and receive windows to 1 MiB per parent/64 KiB
per stream. Header/setup deadlines and active owner/idle cancellation remain
bounded. `noSSEHeader: true` suppresses the explicit SSE Content-Type only;
identity encoding, no-store and no-buffering invariants remain. Arbitrary
response/header templates, periodic stream-up response padding and browser CORS
remain pending; OPTIONS is not a new unauthenticated forwarding path.

Normal request-body EOF retains response drain and parent reuse. Closing an
incomplete body interrupts its read deadline; a body that already reached EOF
does not receive an artificial read timeout that could cancel HTTP/1.1's final
response flush. Per-stream cancellation interrupts protected dialing. Engine
close joins protocol handlers, closes admitted sockets and preserves zero
active admission. VLESS/VMess/Trojan UDP-over-stream and MUX/XUDP retain bounds;
Shadowsocks generic XHTTP is TCP, with separately configured native UDP retained
through the existing bounded dual-bind/rollback path.

HTTP3 shares the same request parser, protected protocol handler and split
session manager. QUIC receives at most 64 KiB per stream and 1 MiB per parent,
with at most min(MaxConnections, 128) incoming request streams and eight
unidirectional streams per parent. Header parsing reserves engine admission
before starting a request worker; overload resets that stream with
H3_EXCESSIVE_LOAD. Incomplete HEADERS expire at ConnectTimeout, while completed
headers clear their parsing deadline. Control-stream handlers join the parent
on close. These quic-go interfaces are recorded in the component patch manifest
and verified in mobile module staging.

HTTP3 download GETs without a Content-Length are accepted only after reading
their actual empty-body FIN within the setup deadline. The ended GET's physical
read deadline is cleared independently of the upload/setup read deadline.
Established stream-up clears both upload deadlines, preventing HTTP/2's setup
write timer from resetting an active session after ConnectTimeout. The existing
flow idle timer and owner cancellation still close stalled established flows.
On h3, Shadowsocks must set `options.udp` to `"false"`: native SS UDP and QUIC
cannot bind the same UDP listener. Generic SS XHTTP remains TCP-only.

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
HTTP3 native tests cover all modes/four protocols, repeated TCP, supported
UDP-over-stream, pre-header admission, incomplete request/control streams and
joined owner shutdown. A timed stream-up regression transfers payloads before
and after ConnectTimeout over h1/h2/h3. Official Xray 26.7.28 also passes the
four-protocol/all-mode h3 matrix and hybrid Vision/inner-TLS/XUDP across the
three modes. This does not establish generic legacy QUIC carrier servers.

Only final full builds are delegated to the workflow. These are local protocol
results; varied public-node Internet and live host route/DNS acceptance remain
separate.

Primary sources:
[pinned XHTTP listener](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/splithttp/hub.go),
[pinned XHTTP configuration](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/splithttp/config.go),
[pinned padding semantics](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/splithttp/xpadding.go).
