# VLESS hybrid encryption server

Version 0.5.15-go adds project-owned VLESS `mlkem768x25519plus` decryption
over raw TCP, optional verified TLS or REALITY, with optional Vision. The
client and server use synchronous bounded record streams; this path does not
launch a proxy subprocess or create per-connection encryption workers/queues.
Go/CLI server startup is implemented; mobile/C ABI server bindings remain work.

## Configuration

```json
{
  "outbounds": [{"tag": "direct", "uri": "direct://"}],
  "final": "direct",
  "inbounds": [{
    "protocol": "vless",
    "listen": "127.0.0.1:4433",
    "uuids": ["<your UUID>"],
    "options": {
      "decryption": "mlkem768x25519plus.native.60-120s.<private key or ML-KEM seed>"
    }
  }]
}
```

`decryption` is opt-in; omitting it or using `none` retains ordinary VLESS.
The wire modes are `native`, `xorpub` and `random`. Server lifetime `0s`
disables resumption; `600s` chooses 300-600 seconds, and `60-120s` chooses that
explicit range. Values are bounded to 0-65,535 seconds. Clients use matching
`mlkem768x25519plus.<mode>.1rtt.<public key>` or `0rtt` encryption settings,
with public keys in the same order. Never distribute server private keys.

Keys are base64url: 32-byte X25519 private keys or 64-byte ML-KEM-768 seeds.
One listener holds a fixed chain of at most eight distinct keys and validates
each relay commitment; this does not implement forwarding between relay
servers. Client offers use the corresponding 32/1,184-byte public keys.
The decryption string is bounded to 20 KiB and each encoded private key to
128 bytes. Optional probability/size and delay rules precede keys, for example
`.100-75-75.100-0-1.`. At most 16 rules and 65,553 total padding bytes are
accepted. Delays obey connection timeout and owner cancellation.

`options.flow=xtls-rprx-vision` permits Vision with encryption even without
outer TLS. After TLS 1.3 classification and record-boundary checks, command 2
ends only the VLESS record AEAD. Parent TLS/REALITY/carrier layers remain;
`random` mode retains direction-separated header masking on origin TLS
ciphertext. Split headers preserve mask position and record boundaries.
UUID/flow policy and UDP-only Vision MUX restrictions remain.

## Authentication, memory and lifetime

Fixed-key exchange authenticates the hybrid ephemeral ML-KEM-768/X25519 offer;
fresh 1-RTT sessions derive forward-secret, direction-separated record keys.
The server negotiates AES-GCM or ChaCha20-Poly1305 from the authenticated
length message; the existing Go client sends AES-GCM. AEAD authenticates
handshake lengths, public keys, tickets, padding and every data header/body.
The stream rekeys at the 96-bit nonce boundary using the authenticated frame.
Full-random mode masks headers with direction-separated AES-CTR streams.

Each configured listener has at most 1,024 live tickets and 8,192 resumed-key
replay entries. Duplicate resumptions with the same ticket/non-forward-secret
key fail atomically, including concurrent requests. Full live replay state
rejects admission without evicting protection. A full ticket cache issues a
zero-lifetime ticket, preserving ordinary 1-RTT data service. Expired entries
are reclaimed on demand, at most once per second; ticket expiry is always
checked individually. No maintenance worker or timer runs for these caches.
Client tickets remain bounded to 1,024 and their identities now include the
endpoint/security/name/path as well as encryption settings, isolating listeners.

An input record is bounded to 16,640 encrypted bytes; output chunks are 8,192
plaintext bytes. Direction-local buffers are allocated lazily and reused.
Independent read/write locks prevent nonce or CTR reuse under concurrent I/O.
Half-close preserves the other direction. Authentication failures close the
stream, and owner shutdown closes tracked sockets and joins existing relay
workers, including incomplete handshakes and configured padding waits. Normal
EOF does not tear down a still-active response direction. Shared routing,
protected dialing, idle handling and admission limits remain in force.

## Acceptance and remaining work

Go race tests passed all three modes, X25519/static ML-KEM chains, 1/0-RTT,
TCP/large atomic UDP, native TLS/Vision, verified inner TLS, parallel payloads,
listener ticket isolation, replay/cache expiry/capacity, malformed settings,
corrupt offers/records, protection failure, cancellation, incomplete-owner
shutdown, ChaCha resumption, nonce-boundary rekey and half-close.
Official Xray 26.7.28 passed five initial configurations with plain/verified-inner-TLS
200,001-byte TCP bodies and UDP/XUDP: native 1-RTT; xorpub/random 0-RTT with
static ML-KEM and Vision; native/random 0-RTT with TLS and Vision.

The initial targeted test did not compile because its fixture referred to a
nonexistent hook field; it now supplies hooks when constructing the engine.
That failed run remains separate from subsequent acceptance. A subsequent
full regression and repeated reference runs exposed intermittent command-2
rejection on wrapped/full-random encrypted Vision. The corrected transition
peels only the VLESS AEAD and preserves parent layers/header masking. Six
unchanged reference repetitions passed after this correction; failure logs
remain retained. REALITY combination and final combined results are recorded
in the capability register. Combined old
client/carrier regression and full race results are recorded in the capability
register, without a local final platform/package build or remote CI claim.
Extra server carriers and automatic stale-ticket connection retries remain
work. No delivered application data is replayed. Loopback checks do not establish
varied public-node Internet or OS host route/DNS recovery.

Primary versioned wire references:
[handshake](https://github.com/XTLS/Xray-core/blob/v26.7.28/proxy/vless/encryption/server.go),
[record format](https://github.com/XTLS/Xray-core/blob/v26.7.28/proxy/vless/encryption/common.go),
[decryption settings](https://github.com/XTLS/Xray-core/blob/v26.7.28/infra/conf/vless.go).
