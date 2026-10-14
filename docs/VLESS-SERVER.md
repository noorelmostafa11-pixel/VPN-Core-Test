# VLESS / Vision server

Version 0.5.13-go adds opt-in Vision to the existing Go VLESS server. No external
proxy engine is used by the runtime. The CLI starts profile inbounds; the Go SDK
uses `Engine.StartServer`. Mobile/C ABI server startup bindings remain pending.

## Configuration

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
    "options": {"flow": "xtls-rprx-vision"}
  }]
}
```

Vision uses the server certificate/key or the explicit REALITY configuration
described in [REALITY-SERVER.md](REALITY-SERVER.md), with TLS 1.3; this listener
disables outer TLS session tickets. The flow policy applies to every configured
UUID (at most 128 per listener). Separate listeners can use different policies;
per-user mixed flows are not added. The client uses `flow=xtls-rprx-vision` or its
`-udp443` client variant, with normal certificate/name verification. An empty
server flow retains the existing raw/optional-TLS VLESS behavior.

## Framing and lifetime

Version/UUID authentication precedes addons and destination handling. Addons
remain bounded to their one-byte length; the flow field is decoded from its
protobuf wire form without adding a protobuf runtime dependency. Truncated,
overflowed, duplicate or incorrectly typed flow fields and unknown flow values
are rejected. Bounded unknown scalar/bytes fields are skipped; protobuf groups
are rejected. Unknown server options are rejected.

Vision TCP requests must present the configured flow. UDP-over-TCP requests use
an empty flow, retaining ordinary packet framing. MUX/XUDP is accepted on a
Vision listener with or without Vision padding, but only UDP subflows may open;
an attempted TCP subflow receives a MUX failure without allocating an upstream.
This prevents MUX from bypassing the listener's TCP flow requirement. A Vision
flow on command-2 UDP is invalid; Vision clients use XUDP or empty-flow UDP.

Each TCP direction owns its padding state. The first padded response contains
the authenticated UUID; command 0 continues padding, 1 ends padding inside TLS,
and 2 switches to raw origin TLS ciphertext. Direct uplink is permitted only
after observing a TLS 1.3 ServerHello in the origin response. Direct downlink
waits for a complete application-record boundary, including split headers and
payloads. The boundary tracker stores only five header bytes; record read-ahead
is bounded before an outer TLS/direct transition, preserving coalesced bytes.
Plain/non-TLS traffic ends padding and continues through the outer TLS session.

Concurrent read/write paths share only an atomic TLS classification. Half-close
follows the write direction's current transport; a TLS close-notify is not sent
into direct raw data. Existing admission, protected routing, queues, MUX
session limits and joined owner/idle shutdown remain in force. Vision
creates no new background worker, timer or global cache.

## Acceptance and remaining scope

Targeted Go race tests passed repeated TCP/UDP transfer and owner close, actual
inner TLS 1.3 with 200,001-byte bodies, fragmented direct boundaries, half-close,
malformed addons, missing flow rejection and UDP-only MUX policy. Official Xray
26.7.28 passed 16 TCP connections per plain/verified-inner-TLS case, eight XUDP
associations per case with 32/1,400/3,800-byte packets, and missing-flow rejection.
The first independent invocation omitted the tests module path and failed to
import; it was a launcher error, corrected before the successful payload run.

The runtime workflow installs a test-only Xray 26.7.28 release asset, checks its
pinned SHA256 and version, and enables independent Xray cases rather than
silently skipping them. It extracts only the reference executable into the
runner's temporary directory; nothing from this reference enters packages or
the runtime. Platform archive hashes are pinned in Get-Xray-Test-Reference.py.
Local checks continue; final full platform/package builds are delegated to the
workflow without waiting for its result. Combined results are recorded in the
implementation register. Loopback tests do not establish varied-node Internet
or Windows route/DNS acceptance.

Additional REALITY camouflage/PQ options, VLESS encryption, server carriers, reverse/fallback
and per-user flow options remain pending. Client implementations of those
existing features are retained. This extension does not declare full parity.

Primary references, pinned to the independent client version:
[VLESS addons](https://github.com/XTLS/Xray-core/blob/v26.7.28/proxy/vless/encoding/addons.go),
[Vision framing](https://github.com/XTLS/Xray-core/blob/v26.7.28/proxy/proxy.go),
[inbound flow policy](https://github.com/XTLS/Xray-core/blob/v26.7.28/proxy/vless/inbound/inbound.go),
[official release](https://github.com/XTLS/Xray-core/releases/tag/v26.7.28).
