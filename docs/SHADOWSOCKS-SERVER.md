# Shadowsocks TCP / native UDP server

Version 0.5.12-go adds native UDP for all 35 existing cipher methods and SS2022
TCP server framing. The executable launches routing-profile inbounds; the Go
SDK uses `Engine.StartServer`. Mobile/C ABI server startup bindings remain
pending. No external Shadowsocks engine or helper process is used.

## Configuration

```json
{
  "outbounds": [{"tag": "direct", "uri": "direct://"}],
  "final": "direct",
  "inbounds": [{
    "protocol": "ss",
    "listen": "127.0.0.1:8388",
    "cipher": "2022-blake3-aes-128-gcm",
    "password": "<your base64-encoded 16-byte key>",
    "options": {"udp": "true"}
  }]
}
```

Run `vpn-core --config profile.json --no-socks`. Generate your own key with
`openssl rand -base64 16` for AES-128, or 32 bytes for AES-256/ChaCha. Client and
server must use the same key. SS2022 accepts fixed colon-separated identity
chains of up to eight AES keys; the configured complete chain is validated on
TCP/UDP requests. ChaCha uses one key. This is not a dynamic multi-user directory.
Legacy cipher/password semantics and existing client URIs are unchanged.

Native UDP is enabled by default, at the same IP/port as TCP. `udp:false` is
expressed as the string `"false"` in `options` and creates no UDP socket/workers.
TCP/UDP startup is atomic: a failed UDP bind rolls back the new TCP listener.
For listen port zero, a collision in the separate TCP/UDP ephemeral allocators
retries at most eight candidates, closing each failed TCP socket. An explicit
port never changes, and owner shutdown stops admission.
Both certificate paths optionally wrap TCP in native TLS; native UDP retains
its Shadowsocks datagram cipher. In ShadowTLS, SS2022 TCP and enabled UOT v2
stay inside the authenticated stream and do not open a native UDP listener.
Unknown options and invalid PSK sizes/chains are rejected.

## Authentication, routing and bounds

SS2022 TCP implements authenticated request/response headers, preserved initial
payload, padding validation and encrypted length/payload chunks. The initial
salt/identity/fixed header is processed in one read, with a uniform TCP reset
on invalid/partial headers. The first response combines its header and actual
payload in one write. Timestamp validity is +/-30 seconds; listener-local salt
state retains accepted requests for 60 seconds, with at most 8,192 entries.
A full live cache rejects admission without evicting replay protection.
Each encrypted direction rejects nonce exhaustion. Body chunks are at most
65,535 plaintext bytes. Cipher choices include both AES-GCM variants and ChaCha.

UDP authentication and address/timestamp validation precede relay admission.
SS2022 sessions are identified by the authenticated eight-byte client session
ID, with a 2,048-packet replay window. Duplicates do not alter return addresses.
Valid network changes update the last client address and keep the direct relay
source socket stable. Server session IDs differ from client IDs and response
counters cannot wrap. Replay/session state is retained for 65 seconds after the
last valid client packet, expiring on a five-second sweep. AEAD2017 UDP also has
listener-wide salt replay protection; historical unauthenticated methods retain
their protocol behavior.

Each listener has at most 128 UDP peers, sharing the engine's connection budget;
direct sockets and routed proxy connections are charged to the same budget.
Each peer queue holds eight packets; excess datagrams may be dropped. Direct
relay sockets are unconnected per family for Full Cone replies. Source metadata
is captured for each queued request, including authenticated network changes.
Proxy cache entries distinguish source IP and route tag, with explicit block
decisions checked before reuse. Invalid input and protected-socket failures do
not fall back to direct traffic. Owner shutdown joins all relay workers.
Stopped relays retain their replay entry until expiry, but rejected new traffic
does not refresh that entry or change its last authenticated return address.

The historical `table` method lazily builds its two immutable 256-byte
permutations once per UDP codec. Concurrent peers share those permutations;
there is no global password cache, timer or extra worker. Ciphers with an IV or
stream position still create independent per-packet cipher state.

UDP wire packets are limited to 65,507 bytes including protocol overhead, so
the maximum application payload depends on cipher/address/header size. Native
UDP does not split oversized datagrams into separate application packets.
Multi-user credentials, additional server carriers and remaining upstream
options are pending. General standalone SS UOT configuration is not added by
this extension; ShadowTLS's explicit UOT v2 path is supported.

## Acceptance

Go tests transfer real UDP payloads through all 35 methods, four sessions each
with 1/1,400/32,000/60,000-byte bodies. SS2022 TCP tests cover all three ciphers,
16 repeated connections per chain configuration, optional verified TLS, owner
loss and AES identity chains. Further tests cover native IPv6, Full Cone replies,
replay without address migration, authenticated migration with stable source
ports, source-CIDR blocking across a cached SOCKS proxy, session/replay limits,
expiry, malformed headers/packets, protection rejection, failed dual-bind
rollback and nonce/counter exhaustion. Embedded ShadowTLS tests cover TCP/UOT
UDP for every modern cipher and v2/v3.

Independent official sing-box 1.14.3, revision
`7054cac5124465ffdb145870d7c01885566711b1`, transfers TCP/native UDP both ways
for three AEAD2017 and three SS2022 methods. Each combination makes 16 TCP
connections carrying 200,001 bytes and eight UDP associations carrying
32/1,400/3,800 bytes. Its client also exercises two/three-key AES identity chains
against the project server. Reference binaries are test-only, never linked or
launched by the runtime. Archive hashes are recorded in [TUIC.md](TUIC.md).

Set `VPN_CORE_REFERENCE_SINGBOX` and run `python scripts/Validate-Go.py`.
The initial Go fixture failures omitted the TLS server name and raw transport;
correcting those fixture settings passed. Independent embedded UOT initially
exposed rejection of its virtual port-zero destination; the exact virtual-host
exception has a header regression while unknown zero-port destinations remain
invalid. A later malformed-header test used an offset from a different randomly
padded header and panicked; its offset now comes from the actual test packet.
That was a fixture error, retained separately from production failures.

The initial full race run and isolated pressure run exposed `table` repeatedly
rebuilding its stable-sort permutation for every datagram, exceeding the same
four-second association deadline on the 60,000-byte body. One isolated run
passed in 15.14 seconds; the three-run process later timed out while sorting.
After the lazy per-codec correction, all three repetitions passed in
1.10-1.28 seconds each, keeping four associations, all four payload sizes and
the original deadline. A separate 32-worker test validates concurrent first
use and 512 packet round trips against an independent Python wire digest.
This is a local race-detector measurement, not a general Internet benchmark.

The subsequent full race run exposed a real automatic TCP/UDP port collision
in an existing legacy TCP case on Windows. The bounded port-zero retry corrects
that startup failure; deterministic real-socket tests force one collision and
eight consecutive collisions, verifying recovery, the attempt ceiling and
rollback. The explicit occupied-port rejection test is retained.

These are local wire/lifecycle results, not varied public-node Internet
or Windows route/DNS acceptance.

Primary wire descriptions:
[SIP022](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/sip022.md),
[SIP023 identities](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/sip023.md).
