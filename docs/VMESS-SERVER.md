# VMess server

Version 0.5.11-go adds an optional Go VMess inbound. The executable, Go SDK,
mobile configuration and C ABI routing configuration use the same server.
No other proxy engine is launched, and no server workers exist when unused.

## Configuration

```json
{
  "outbounds": [{"tag": "direct", "uri": "direct://"}],
  "final": "direct",
  "inbounds": [{
    "protocol": "vmess",
    "listen": "127.0.0.1:8443",
    "uuids": ["12345678-1234-4567-9234-567812345678"],
    "cert_file": "server-cert.pem",
    "key_file": "server-key.pem"
  }]
}
```

Run `vpn-core --config profile.json --no-socks` for server-only operation.
The example UUID is synthetic. Listen addresses must be literal IPv4/IPv6.
Both certificate paths enable TLS 1.2/1.3; omitting both enables raw TCP.
VMess client URI and TLS trust/pin settings retain their existing behavior.

`uuids` accepts 1-128 distinct UUIDs. AEAD authentication is the default.
Legacy clients are accepted only with explicit `options: {"alter-id":"2"}`.
The value is 0-64, with at most 256 total primary/derived legacy identities per
listener. Modern AEAD clients remain valid on a legacy-enabled listener.
Unknown options, duplicate users and unused password/cipher fields are rejected.

## Wire and ownership

- Commands: TCP, fixed-destination UDP and MUX/XUDP; see [MUX-SERVER.md](MUX-SERVER.md).
- Body security: AES-128-GCM, ChaCha20-Poly1305, AES-128-CFB and none.
  Unframed zero security is accepted for TCP only, matching the wire command.
- Framing: chunk stream, SHAKE128 length masking, global padding and authenticated
  chunk lengths for AES-GCM/ChaCha. AEAD response headers and legacy CFB
  response/body continuity are preserved; authenticated empty chunks end streams.
- Header sizes: 42-512 bytes for AEAD, including destination-less MUX and all
  0-15 padding lengths. Checksums, reserved fields, commands and option combinations
  are validated before forwarding application data.
- Timestamp authentication: +/-120 seconds. AEAD identities and session key/IV
  pairs are replay-protected for 241 seconds in a bounded 8,192-entry cache.
  A full live cache rejects admission rather than evicting replay protection.
  Legacy HMAC timestamps are indexed lazily per listener, without a timer.
- Authenticated body nonces never wrap: a direction closes after 65,536 chunks.
  TCP writes split at 16,000 bytes. UDP bodies stay atomic, up to the 65,507-byte
  datagram bound and the 65,535-byte encrypted frame bound including padding.
  Excessive datagrams are rejected; they are not silently split into packets.
- TCP/UDP forwarding uses the engine's current routing, protected sockets and
  shared connection budget. Owner close cancels and joins listener/flow workers.

Server-side WebSocket/gRPC/XHTTP and other carriers remain pending. This inbound
does not claim complete Xray/sing-box server-option parity or public-node Internet
acceptance. The existing VMess client/carrier implementations are retained.

## Independent acceptance

Synthetic loopback fixtures use independently installed clients:

- Xray 26.7.28, commit `5ca6f4b`; Windows executable SHA256
  `1d9674327972a21afd4c906a7a72bb0856935aa9e0227c87f34f03d11a88bddf`.
  AES/ChaCha raw TCP and verified TLS, default XUDP and AuthenticatedLength
  each transfer actual echoed payloads. Each cipher/transport combination makes
  16 TCP connections and 32 UDP associations with 32/1,400/3,800-byte bodies.
  MUX tests transfer 200,001 bytes per TCP session in four eight-session batches
  for both ciphers; VLESS shares the same independent MUX acceptance.
- Official V2Ray 4.45.2; Windows executable SHA256
  `28a3c3c773a3aa41b51c0a1ffccbb0c8fe54f972c081bfc81c827bfc4d9dc0e6`.
  Legacy alter-ID authentication, all five security modes, raw TCP and verified
  TLS transfer echoed payloads. Framed modes make 32 UDP associations each.
  UDP bodies are 32/1,400/1,800 bytes because this reference has 2 KiB buffers.
  Go acceptance independently covers atomic packets up to 60,000 bytes.

The first XUDP run exposed a project header-size rejection with short valid MUX
headers. Its correction has a deterministic test for every header padding size.
The first legacy-reference fixture also used unsupported modern pin fields and
overlarge packets for V2Ray 4; it was corrected to trust the generated CA and
respect the reference packet buffer, without relaxing core TLS verification.
Failure logs remain in local engineering evidence.

Set `VPN_CORE_REFERENCE_XRAY` and `VPN_CORE_REFERENCE_V2RAY4` to the reference
executables and run `python scripts/Validate-Go.py`. References are optional test
tools, not runtime dependencies. Race tests include authentication failures,
timestamp bounds, replay capacity, corrupt headers/body, nonce exhaustion,
protection denial, repeated close and cancellation of partial frames.

Wire reference sources:
[Xray VMess encoding](https://github.com/XTLS/Xray-core/tree/5ca6f4b/proxy/vmess/encoding),
[Xray client options](https://github.com/XTLS/Xray-core/blob/5ca6f4b/proxy/vmess/outbound/outbound.go),
[V2Ray 4.45.2](https://github.com/v2fly/v2ray-core/tree/v4.45.2/proxy/vmess).
