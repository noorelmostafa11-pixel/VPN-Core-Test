# Standalone legacy HTTP/2 and h2c

Base: `8ef6465870c7c6e1964d353b65b0078cfa198fd5` plus this batch. Before the
patch, all four selector tests failed: `http`/`h2` were removed, while
`http2`/`h2c` were unknown. The failing log is retained outside Git.

## Scope and configuration

This is a separate `transport/internet/http` implementation, not an alias for
XHTTP stream-one, HTTP Upgrade, gRPC or HTTP/3. It carries proxy protocol bytes
unchanged in one HTTP/2 request and streaming200 response, without another wire
codec. `http`, `h2` and `http2` select the same historical transport. Security TLS
requires certificate verification and negotiated `h2`; security none uses
prior-knowledge cleartext HTTP/2. The additional `h2c` selector rejects TLS rather
than silently contradicting its name. No TLS failure downgrades to cleartext.

Example outbound stream settings (the proxy settings are independent):

```json
{
  "network": "http2",
  "security": "tls",
  "tlsSettings": { "serverName": "tunnel.example" },
  "httpSettings": {
    "host": ["tunnel.example"],
    "path": "/legacy",
    "method": "PUT",
    "headers": { "X-Example": ["one", "two"] },
    "read_idle_timeout": 30,
    "health_check_timeout": 10
  }
}
```

Use `network: "h2c"`, `security: "none"` for intentional cleartext. Without
TLS, confidentiality/authentication must come from the proxy protocol; h2c does
not provide them. No default network or security for other transports changes.

- Omitted method defaults to PUT. Custom body-capable methods such as PATCH
  work on both endpoints; GET/HEAD/CONNECT/TRACE are rejected explicitly.
- Omitted path is `/`; a missing leading slash is added. Percent-encoded paths
  and raw query strings are preserved. Inbounds match exact escaped path/query
  and configured method, not the old upstream listener's broad path prefix.
- Host accepts a string or list. Outbounds choose a listed authority, or default
  to the destination authority (not historical upstream's `www.example.com`).
  Empty inbound host lists accept any authority; listed hosts are case-insensitive
  and explicit ports must match. IPv6 bracketed authorities are supported.
- Headers accept string/list values; all values are transmitted, not randomly
  selected or silently overwritten. Transport-managed and hop-by-hop fields,
  including Host, Content-Length, encodings and Connection, are rejected; use
  `host` for authority. Header injection and duplicate case-folded names fail.
- Metadata is limited to64 hosts,64 headers,16 values/header and8192 configured
  bytes (including per-field overhead); path2048 bytes, host512 bytes, method32
  bytes. JSON and direct protobuf inputs receive the same validation.
- Read-idle0..600 seconds and ping timeout0..60 seconds map to the existing HTTP/2
  library. A nonzero ping timeout requires nonzero read-idle. This batch tests
  setting preservation/guards, not a new independent ping scheduler.
- HTTP/2 + REALITY is not implemented in this batch: JSON and runtime security
  checks reject it explicitly. Existing REALITY/TCP/XHTTP/gRPC is not modified.
- HTTP/1.1 Upgrade, HTTP/3 and standalone legacy QUIC are not implemented by this
  transport. No whole native engine, fallback process or new module dependency.

## Connection ownership

Each outbound logical tunnel owns one physical HTTP/2 connection. No process-
global destination/client cache or cross-tunnel connection pooling is introduced.
Two zero-buffer Go net.Pipes provide renewable, directional client deadlines and
CloseWrite upload EOF while the response remains readable. The response worker,
request body, physical connection and cancellation are owned by that tunnel.
There are no unbounded application-level upload/download queues. This choice is
not a performance/size reduction or cross-tunnel multiplexing claim.

Inbounds support up to128 simultaneous streams per physical connection, bounded
HTTP/2 flow-control/header buffers and a4-second initial handshake/preface bound.
Idle parents have a120-second server idle timeout. Active parents and handlers
are tracked; listener close cancels them, unblocks stalled writes and joins them.
ResponseWriter use is serialized and finished before its handler returns. TLS
connection state is preserved through the preface wrapper for HTTP/2 validation.
Socket settings, final-mask dialing/listening and the existing trusted-XFF policy
are passed through; final masks and XFF combinations are not independently
accepted by this batch's tests. Outbound TCP metadata remains the actual peer.

Redirects, non200 responses and compressed/duplicate Content-Encoding responses
fail; there is no automatic redirect or request replay. Cleartext listeners do
not accept an HTTP/1.1 request as a successful tunnel.

## Comparison and provenance

Compared with pinned main `b066df12`'s `core/http2_server.go`,
`core/server_transport.go` and `core/xhttp.go`'s LegacyHTTP PUT branch. Historical
upstream references are [the client](https://github.com/XTLS/Xray-core/blob/v1.8.24/transport/internet/http/dialer.go),
[server](https://github.com/XTLS/Xray-core/blob/v1.8.24/transport/internet/http/hub.go)
and [schema](https://github.com/XTLS/Xray-core/blob/v1.8.24/transport/internet/http/config.proto).
Only the six-field schema is restored with original message/field names and IDs;
the old global client cache, unsynchronized waiting reader and broad path-prefix
handler are not imported. Repository history, MPL license and module path remain.
The already-pinned `golang.org/x/net/http2` handles HTTP/2 framing and flow control.

## Local evidence and one known failure

Go1.27.1 Windows amd64, GCC16.2 for race detection:

- Repeated new tests, race,count10: HTTP/2 transport10.616s and config3.465s.
  Independent-peer client cases cover h2c, standard TLS and uTLS with certificate
  pins; inbound cases cover h2c/TLS. Each transfers120003 exact bytes with a
  server-first greeting, fragmented writes and upload EOF before download ends.
- Full configured VLESS inbound/outbound h2c against an independent TCP echo
  also passes (included in the repeated set). Its test-only Freedom rule permits
  only the exact loopback target/port; production private-address policy is intact.
- Negative cases cover method/host/exact path/query, malformed settings/protobuf,
  compression, redirects, wrong pins, incompatible negotiated ALPN and missing
  TLS settings. Cancellation before/after headers, actual blocked upload deadline,
  renewed client read deadline, eight simultaneous inbound streams, blocked
  response Close, late writes and stalled-preface listener cancellation pass.
- Broader affected-package run: HTTP/2 transport9.935s, transport internet3.249s,
  config10.824s and core106.137s passed; distro/all compiled with no tests.
  **The command as a whole failed**, because the TLS package's existing external
  `TestECHDial` failed. Do not call this run or the full TLS suite green.
- That unchanged test performs ten concurrent DNS ECH lookups for
  `encryptedsni.com` through `1.1.1.1`, then HTTPS to Cloudflare. DNS returned no
  usable ECH config; it panicked on `tls: malformed ECHConfigList`. The TLS
  source and its existing transport dependencies have no changes in this batch;
  its standalone test dependency list does not include the new HTTP transport.
  This establishes isolation from the new transport, not successful Internet/ECH
  acceptance. The test was not edited, skipped in that full run, or retried until
  green. The original failing output is retained outside Git.
- A separate, explicitly selected offline TLS certificate/hash/pin/expiry suite
  passed race2.729s. This is not a replacement claim for the failed full suite.
- Existing selected TLS/pinned TLS/uTLS/WebSocket/gRPC/multi-gRPC/raw HTTP header
  scenarios passed race65.991s. KCP scenarios were not part of this selection.
- Vet passed the new transport, transport internet, TLS, config, core and all
  distro registration. No compatibility workflow/check/wire runner is touched.

The first compile attempt used the project net alias for standard net.Pipe and
ErrClosed, and assumed TLS.Server's net.Conn return exposed TLS-only methods. Those
local compile errors were corrected explicitly. An initial formatting invocation
used unsupported literal Windows globs; explicit file paths were then formatted.
No protocol assertions, deadlines or tests were weakened.

- Final source focused race rerun: HTTP/2 transport4.659s, config3.231s; final
  vet passed. Handwritten changed Go files pass gofumpt; diff whitespace passes.
- Raw protoc33.5/plugin1.36.11 regeneration is identical: config.pb.go SHA256
  `2a67167cc28c57ef3715bc61c8849b62f1379c1199b92ced94da47c05fd63b58`.
  The first hash comparison detected gofumpt's generated-file import/var-group
  reformatting. The final file retains raw generator formatting; a second
  generation is identical. No schema/behavior change was used to resolve it.
- The same final source compiled to a full-feature Windows CLI with CGO0,
  trimpath and stripped symbols. Local version invocation passed, reporting
  `8ef6465-dirty`, not an incorrectly labeled clean future commit. Retained
  outside Git only:35185152 bytes, SHA256
  `ab1417cac17a0990aaf055f7fb30337ac1545178667330d4deee605afd20c0ef`.
  No size/performance improvement or distributable package/release is claimed.

No Linux/macOS runtime, whole-repository CI, Android/package/release, private-node,
main-peer interoperability, UDP-over-carrier acceptance, Internet, SDK/ABI or full
protocol parity is claimed.
