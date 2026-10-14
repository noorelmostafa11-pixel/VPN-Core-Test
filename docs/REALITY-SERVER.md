# VLESS REALITY server

Version 0.5.14-go implements REALITY client authentication and authenticated
TLS 1.3 using the native Go TLS stack, with VLESS TCP/UDP/MUX and optional
Vision. No external core or additional TLS fork is launched or linked.
This implements interoperable authentication/data transfer; exact target
ServerHello/record-shape mirroring and additional upstream options remain work.

## Configuration

```json
{
  "outbounds": [{"tag": "direct", "uri": "direct://"}],
  "final": "direct",
  "inbounds": [{
    "protocol": "vless",
    "listen": "127.0.0.1:4433",
    "uuids": ["<your UUID>"],
    "options": {"flow": "xtls-rprx-vision"},
    "reality": {
      "private_key": "<your base64url-encoded 32-byte X25519 private key>",
      "server_names": ["your-target.example"],
      "short_ids": ["<your even-length hexadecimal ID, at most 16 characters>"],
      "target": "your-target.example:443",
      "max_time_diff_ms": 30000
    }
  }]
}
```

Use `vpn-core --config profile.json --no-socks` or `Engine.StartServer`.
The client receives only the public key, matching SNI/short ID and UUID; never
distribute the server private key. `reality` is exclusive with certificate/key
files and valid only on VLESS. Omit `flow` for ordinary VLESS; configured Vision
retains its TCP flow and UDP-only MUX policy. Unknown JSON fields/options are
rejected by the existing profile reader. Mobile/C ABI server bindings remain
pending.

The configured fallback is one explicit TCP destination; a TLS 1.3 HTTPS target
is appropriate for ordinary HTTPS visits. It is not selected from a request
destination. Server names are bounded to 32 entries (253 bytes each), and short
IDs to 128 eight-byte values. Hex IDs are right-padded with zeros; duplicate
padded IDs/names are rejected. An empty short ID or SNI is allowed only when
explicitly configured. The default timestamp window is 30 seconds; configurable
positive windows are capped at five minutes. TLS session tickets are disabled.

## Authentication, bounds and native TLS

The ClientHello's X25519 share or the X25519 part of its hybrid share derives
the REALITY auth key with HKDF-SHA256. AES-GCM authenticates the 32-byte session
ID against the original ClientHello with that ID cleared. Timestamp, reserved
byte, allowed name and short ID are checked before proxy processing. The
Ed25519 certificate carries the HMAC-SHA512 authenticator expected by clients.
TLS CertificateVerify, Finished and record authentication stay enabled.

REALITY fixes the CertificateVerify signature to Ed25519 despite browser
signature advertisements. The authenticated Go 1.27 adapter sets the parsed
signature-selection list through ClientHelloInfo, while Go retains the exact
original ClientHello transcript. This applies only to authenticated REALITY,
does not rewrite wire bytes and does not change ordinary TLS policy. Pinned
Go-version integration tests guard this implementation-sensitive boundary.

ClientHello assembly is limited to 16 records, a 65,535-byte message, 128
extensions and 128 KiB of prefetched wire data. Complete original records and
extra bytes are preserved for native TLS or fallback, including fragmented
headers. Listener-local replay state has at most 8,192 entries retained for
twice the timestamp window plus one second. A full live cache rejects admission
without replacing replay protection; expired entries are reclaimed on demand.
It has no maintenance worker or global cache.

Invalid or ordinary TLS clients relay only to the configured target. That
connection uses protected socket/resolver hooks, the existing admitted flow,
tracked closure, idle handling and joined owner shutdown. Protection failure
does not try an unprotected connection. Authenticated clients continue to UUID/
flow validation and normal routing; fallback clients cannot choose a proxy
destination. No OS route/firewall changes are introduced.

The native client profile previously exposed parsed hello fields without raw
bytes, so REALITY signing failed before handshake. It now serializes that same
native hello before computing its authenticator. Browser profiles keep their
existing serialization, and normal TLS/REALITY verification is retained.

## Acceptance and remaining work

Targeted Go race tests passed seven client profiles, with/without Vision, eight
TCP connections and four UDP associations per combination; UDP checks retain
large atomic payloads. Further tests verify ordinary authenticated HTTPS
fallback bodies, owner loss/protection rejection, corrupted/expired/future/SNI/
short-ID authentication, bounded replay state, settings and fragmented input.
Official Xray 26.7.28 passed plain/verified-inner-TLS TCP and UDP/XUDP, both flow
modes. Initial standard-TLS Ed25519 selection failures and native-hello signing
failures remain recorded separately from the corrected tests.

Exact decoy handshake/record mirroring, ML-DSA-65 server signatures, client
version restrictions, PROXY headers, UNIX destinations, custom fallback rate
limits and additional server carriers are not implemented by this extension.
Do not treat authenticated payload interoperability as a complete camouflage
or all-upstream-options result. Local checks remain separate from varied-node
Internet, censorship resistance and Windows route/DNS acceptance. Final full
builds belong to the workflow; normal local race/wire checks continue.

Primary references:
[pinned client authenticator](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/reality/reality.go),
[REALITY handshake/signature](https://github.com/XTLS/REALITY/blob/main/handshake_server_tls13.go),
[native Go TLS](https://pkg.go.dev/crypto/tls).
