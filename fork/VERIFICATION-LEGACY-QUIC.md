# Standalone legacy QUIC stream carrier

Date: 2026-10-17. Parent: `e41f9c3b02345246e5aac24cf0f6d04441b8f755`.
This adds an independent `quic` transport. It is not an HTTP/3, XHTTP, Hysteria
or UDP-proxy alias. Existing transports and their security defaults are unchanged.
This is the basic-transport batch's evidence record. The later
[typed-header batch](VERIFICATION-QUIC-TYPED-HEADERS.md) adds historical protobuf
input and records its own final-source validation.

## Sources and wire contract

The packet encryption contract matches pre-removal Xray at
`ab3c00e96b3af6885c09acfdd1f8d36e60d90bad` and pinned native main `b066df12`:
SHA256(key + `xray-quic-salt`), AES-128-GCM using the first16 key bytes or
ChaCha20-Poly1305 using all32, with a random nonce before each ciphertext/tag.
`none` disables only this outer packet AEAD, not QUIC's mandatory TLS encryption.
Headers are outside the AEAD. Fixed camouflage layouts match main's
`core/packet_header.go`: none, SRTP, uTP, DTLS, WeChat/WeChat-video, WireGuard and
DNS. WeChat-video is an alias, not another wire format. These are camouflage,
not real SRTP/DTLS/WireGuard/DNS sessions or authentication mechanisms.

The existing pinned `github.com/apernet/quic-go` supplies IETF QUIC streams.
No dependency, modern QUIC implementation, native engine or fallback executable
is added or replaced. Upstream history/module/license remain intact.

One dial owns one socket/QUIC session/stream; there is no global pool keyed only
by endpoint. A listener accepts up to32 bidirectional streams per connection,
does not advertise unidirectional streams or QUIC datagrams, and joins its owned
accept workers on close. Per-stream close preserves queued send data and does
not close a sibling stream. Upload half-close, renewable deadlines, context
cancellation and failure cleanup are implemented. Per-dial handshakes are bounded
to four seconds; idle QUIC sessions expire after60 seconds. Existing system DNS
resolution/socket behavior is reused, not claimed newly bounded by these tests.

GSO and path-MTU discovery are disabled for this packet-rewriting transport;
packets cannot bypass the wrapper through raw UDP/OOB methods. Wire buffers are
bounded, malformed/authentication-failed packets are discarded, and oversize
reads are not truncated into a different QUIC packet. Write counts refer to
application packet bytes, not added camouflage/nonce/tag bytes. Large DNS
camouflage may require network fragmentation; universal MTU acceptance is not
claimed.

## Input and security

JSON selects `network: quic` and `quicSettings` with packet `security`, `key`
and `header: {type, domain}`. The stream's separate `security: tls` retains the
existing certificate/pin/root policy, configured ALPN and TLS1.3 requirement.
Unknown packet cipher/security is rejected, never changed to NONE. REALITY is
not a supported QUIC pairing and is not replaced by ordinary TLS.

An explicit QUIC profile without stream TLS settings uses the historical
`quic.internal.example.com` internal-certificate mode. It is encrypted TLS1.3
but does NOT authenticate the server certificate, and is not recommended as an
authenticated Internet transport. This mode is chosen from its initial profile
metadata only; a failed explicit TLS certificate/pin check never enters it.
Other protocols' certificate policy and original outbound public-address guards
remain unchanged. No allowInsecure option is restored globally.

Node URIs select the transport automatically. QUIC-specific query names include
`quicsecurity`, `quickey`, `headerType` and `headerdomain` (documented aliases are
handled). Legacy VMess JSON share links use `net: quic`, `host` for packet cipher,
`path` for packet key and `type` for header. Conflicting/unknown metadata is
rejected with sanitized errors. There is no feature-enable switch, protocol
guessing or weaker-security retry based on a failed connection.

Original ignored `quicSettings` fields, including malformed values, stay ignored
on other transports; a `method` override controls selection. The original shared
behavior fixture is unchanged. Existing negative tests that formerly treated
all QUIC as missing now use an unknown transport/invalid QUIC cipher, retaining
their negative assertion while allowing the newly implemented transport.

## Explicit remaining limits

- Explicit client browser/uTLS fingerprints in QUIC are not implemented. They are
  rejected, not silently mapped to stdlib TLS or ChromeParrot. Default/stdlib
  QUIC TLS and its original certificate settings are supported.
- Historical QUIC protobuf fields1/2 retain their meaning. The follow-up batch
  implements the seven known typed-header messages in field3, independently of
  the JSON/URI selectors in fields4/5. No activation flag is needed. See its
  separate record for bounds and historical DNS semantics; this still does not
  establish full old protobuf/application/mobile ABI compatibility.
- Custom modern `quicParams` tuning is not implemented for this legacy carrier;
  it is rejected rather than silently ignored. Existing modern paths retain it.
- Packet keys are bounded to1024 bytes and DNS camouflage domains to254 bytes.
  The tested runtime is Windows. Proxy-level UDP over this carrier, private
  nodes, main executable interoperability, mobile and foreign runtimes are not
  claimed validated by the checks below.
- A QUIC stream is not visible to its peer until its first real application
  byte. No marker byte is invented to force server-first behavior. VLESS's real
  request header opens the stream before the target's server-first greeting.

## Checks

Final-source environment: Go1.27.1 Windows/amd64, GCC16.2 for race detection.

- Full affected race packages PASS: conf11.134s,serial10.367s,main10.533s,
  core165.870s,legacyQUIC17.629s,HTTP2 17.598s,internet4.447s,
  XHTTP8.510s,Hysteria5.704s,exit0. Not a whole-repository/full-TLS command.
- New QUIC tests repeated five times with race detection PASS: QUIC38.482s,
  conf9.062s. Vet of the same affected packages PASS,exit0,no diagnostics.
- The exact unchanged shared fixture on pinned original Xray PASS race7.810s;
  the fork runs it in its full configuration package above.
- Parser fuzzing PASS6494 executions,2 workers,5s requested,11.473s total after
  compilation,4 new interesting corpus cases and no failure. This is bounded
  fuzz coverage, not a security audit or complete input-space proof.
- Same-source CLI compilation PASS Windows/amd64, Linux/amd64, Darwin/arm64,
  CGO0,trimpath,stripped. Windows CLI version/config check PASS,ordinary `.uri`
  auto-detection and ConfigurationOK,exit0. Foreign builds are not runtime tests.
  Binary outside Git: `xray-fork-quic-final-20261017.exe`,35332096 bytes,
  SHA256 `ed9a2e92a720a75cf06cc08f6fdaf4d3cd5984347fd4f6f4a3d42465cfdb96ba`.
  Version is `e41f9c3-dirty`, not a future clean-commit binary. No size reduction,
  release/package/mobile job or foreign runtime acceptance is claimed.

-20 unchanged original scenarios PASS race191.243s,exit0: modern VMess,
  Shadowsocks/SOCKS TCP/UDP/Mux/routing and VLESS/TLS/Vision/REALITY. The original
  REALITY scenario retains its public target; this is not general Internet,
  private-node or full-TLS-suite acceptance. No KCP/ECH scenario selected.

Basic-transport batch source fingerprint
for1205 Go/protobuf/module paths:
`407f7ba74b2f0f4eaeef9629d78c91f5eea5ac0e8f41262256f113a05f63b53b`.

- Independent transport peers cover both roles across3 packet ciphers and8
  header names (48 endpoint cases). Each uses a real opening application byte,
  then a server greeting, fragmented exact120003-byte upload/download and FIN.
- Independent packet oracles use fixed header literals and the SHA256 output
  separately checked with .NET, across1/32/1400/3800-byte payloads in both
  directions. Header golden bytes, malformed/oversized packets, invalid protobuf
  selectors, bad TLS pins/settings/version and unsupported fingerprints are
  checked. No production encryption/header encoder is reused by the oracle.
- A deterministic packet schedule drops packet5, duplicates7 and reverses9/10.
  Exact payload checks pass only when all three fault counters prove they fired.
- Two streams on one independent session verify sibling isolation. Active
  stream read/write deadlines renew; cancellation unblocks a real flow-control-
  stalled write/read, and four concurrent listener closes join with no retained
  sessions. A blackhole test proves a QUIC Initial was sent before cancellation.
- VLESS core JSON/URI cases use a separate server-first TCP echo and exact
  120003-byte payloads. URI/config matrices cover both share-link forms and all
  packet cipher/header combinations without private nodes or keys.

Raw protoc33.5/protoc-gen-go1.36.11 regeneration is identical, SHA256
`4a5a254eaf487f5f2f4528bf05ea103273d17b1a4113e9a8ace151936059ea22`.
Generated output is not passed through handwritten-source gofumpt rewrites.
Original behavior fixture SHA256 remains
`f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.

Retained failures: the before-test rejected the removed QUIC selector. The first
local compile caught a removed TLS AllowInsecure struct field and the current
two-result certificate helper; these were corrected within the new transport,
not by restoring removed TLS APIs. A regeneration check caught gofumpt rewriting
generated import/var layout; raw deterministic protoc output was restored and
all final checks use it. No existing assertion/deadline or original transport
was weakened; no protocol failure was retried until green.

Private evidence uses `xray-quic-` prefixes: before, first-config, config,
first-runtime, expanded, lifecycle-config, final-repeated, final-affected,
final-scenarios, original-baseline, final-vet, final-build, final-cli,
final-crossbuild and final-fuzz. All binaries/evidence stay outside Git.
The known external ECH failure is unchanged, not rerun or relabeled green here.
No compatibility workflow/check/wire runner is edited, dispatched or monitored.
Only documentation changed after the final-source tests and builds.
