# ShadowTLS v2/v3 and Shadowsocks

Project-authored Go client/server based on the MIT ShadowTLS wire design,
version **0.2.25**, revision `dee3a5a819d6f56cfdd56c44a0d42be186c44238`.
Primary descriptions: [v2](https://github.com/ihciah/shadow-tls/blob/v0.2.25/docs/protocol-en.md)
and [v3](https://github.com/ihciah/shadow-tls/blob/v0.2.25/docs/protocol-v3-en.md).
The upstream MIT notice is preserved in `third_party/shadow-tls-LICENSE.txt`
and copied into binary license snapshots. No GPL ShadowTLS implementation or
sing-box engine is linked. The reference executable is test-only.

ShadowTLS carries TCP records, with Shadowsocks providing the payload cipher
and destination request. Client syntax:

```text
shadowtls://shadow-password@vpn.example:443?version=3&sni=handshake.example&method=aes-256-gcm&ss-password=payload-password&uot=2
```

Existing Shadowsocks SIP003 URIs also accept:

```text
plugin=shadow-tls;version=3;password=shadow-password;host=handshake.example;uot=2
```

Percent-encode the plugin value in a URI, including its semicolons. Supported
plugin options are `version`, `password`, `host`/`sni`, `fp`/`fingerprint`,
`alpn`, `uot`, and certificate pins/names. Unknown options are rejected.
An unsupported outer carrier, extra mask or plugin mux is not silently ignored.
The regular node URI and Shadowsocks cipher choices from main remain supported.

V2 authenticates the switch with the first eight bytes of the handshake HMAC.
Authenticated leftover TLS records are filtered before interpreting Shadowsocks
data. The checksummed uTLS component adds a bounded AEAD-only residual-record
primitive; unsuccessful verification does not advance the TLS sequence or emit
a TLS alert. V2 supports TLS 1.2/1.3 as allowed by the handshake backend.

Since 0.5.11, the v2 client also consumes authenticated TLS 1.3 residual records
before sending its switch challenge. Some independent servers retain only their
current and previous TCP-write digests; two post-Finished ticket writes can
otherwise evict the digest the client used. A bounded 32 KiB reader preserves
read-ahead, with at most eight authenticated residual records. The quiet window
is twice the observed TCP/TLS setup duration, bounded to 5-250 ms and still
subject to the overall connection deadline. No application payload is retried.
This introduces a small v2-only setup wait; other protocol paths are unchanged.
Certificate checks and the configured ClientHello fingerprint are retained.
Authentication, partial records and record-limit failures abort before payload.

V3 signs ClientHello's 32-byte session ID, authenticates the handshake server
using ServerRandom, and verifies direction-specific chained tags on every data
record. Record separation is included in the chain, rejecting tampering,
reordering, replay and slicing. Strict TLS 1.3 is required; an unauthenticated
server receives no user payload. Chrome is the default fingerprint. Native
Go/unsafe ClientHello customization is not supported for v3 and is rejected;
the existing supported uTLS profiles can be configured. TLS certificate roots,
names and pins remain enforced. V1, non-strict v3/TLS 1.2, wildcard SNI routing
and multi-user v3 credentials remain future extensions. ECH is not implemented
for this ClientHello signature path and is rejected rather than ignored.

UDP is optional **UOT v2** inside the authenticated Shadowsocks TCP stream,
enabled by `uot=2` on both embedded peers. It never sends raw UDP outside the
ShadowTLS carrier. Without that option, UDP dialing returns `SHADOWTLS_TCP_ONLY`.

Embedded server example:

```json
{
  "protocol": "shadowtls",
  "listen": "0.0.0.0:443",
  "password": "shadow-password",
  "cipher": "aes-256-gcm",
  "options": {
    "version": "3",
    "handshake": "handshake.example:443",
    "ss-password": "payload-password",
    "uot": "2"
  }
}
```

The handshake backend provides its actual TLS certificate; the core does not
generate a substitute. Its socket is protected and the handshake has a deadline.
Unauthenticated traffic remains a bounded TCP relay to that fixed backend.
The embedded payload server currently supports legacy and AEAD2017 Shadowsocks
TCP methods. SS2022 embedded servers remain pending. Alternatively configure
`options.data-server` as an explicit external data backend and omit `cipher`,
`ss-password` and `uot`; that relay can carry another backend protocol without
pretending the core implements that backend's server.

Connections use the engine's shared budget and routing; handshake frame lengths,
switch attempts and challenge history are bounded. No ShadowTLS workers run
when the feature is unused. On switching, the handshake reader is interrupted
and joined before payload writes begin. Close joins relay workers and restores
their flow budget. This protocol does not add a separate multiplexing layer.

Local payload tests passed for v2/v3, 32 connection/close cycles per version,
UOT UDP through 60 KiB, owner loss, trust/auth/protection rejection and handshake
timeout. V3 mutation/replay/slicing rejection tests passed.

Independent sing-box **1.14.3** / revision
`7054cac5124465ffdb145870d7c01885566711b1` passed TCP/UOT UDP in both directions,
v2/v3, and both standalone and SIP003 client configuration. The synthetic TLS
certificate/name is verified. Its archive hash is recorded in [TUIC.md](TUIC.md).
With TLS 1.3 session tickets enabled, the reference v2 client produced a
Shadowsocks authentication failure against our server; the v2 reference-server
fixture therefore disables backend tickets. Our v2 client reference tests keep
tickets enabled. This observed interoperability boundary is retained, not
counted as an unconditional v2 all-options pass. Independent Windows UDP tests
use payloads through 3,800 bytes, separately from the Go 60 KiB tests.

The 0.5.11 combined suite exposed a further v2 client failure with enabled backend
tickets after five successful sessions. Increasing read-ahead alone failed, as
did disabling advertised resumption (the backend still emitted tickets). Both
attempts were reverted. After the authenticated pre-switch drain, the expanded
independent fixture passed 64 sequential connections for both standalone and
SIP003 v2 clients with the backend tickets still enabled. Deterministic Go tests
cover coalesced/delayed records, no-ticket peers, authentication rejection,
partial records and the eight-record ceiling. Initial failures remain recorded.
The reference v2 client's server-direction ticket limitation described above
remains separate. Backends delaying tickets beyond the bounded quiet window
still require wider acceptance; this is not an all-options compatibility claim.

Reference digest behavior:
[sing-shadowtls v2 hash state](https://github.com/SagerNet/sing-shadowtls/blob/a9c0127d5c99/v2_hash.go).

Run `test_shadowtls_reference.ShadowTLSReferenceTests` with
`VPN_CORE_REFERENCE_SINGBOX` pointing to the official executable. These are
local payload results; public-node and Windows route/DNS acceptance are separate.
