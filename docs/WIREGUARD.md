# Embedded WireGuard

The Go engine embeds the official MIT licensed wireguard-go device and its
gVisor adapter, pinned to
`golang.zx2c4.com/wireguard` `v0.0.0-20261006164505-2631ce99a06f`.
The prior dependency on its TUN device types alone was not WireGuard protocol
support. This extension adds authenticated encrypted client and server paths.
No external executable, OS WireGuard adapter or route change is required by
these protocol endpoints.

Client URI:

```text
wireguard://<percent-encoded-base64-private-key>@peer.example:51820?public-key=<percent-encoded-base64-peer-public-key>&local-address=10.71.0.2/32,fd71::2/128&dns=10.71.0.1
```

`wg://` is an alias. Keys are standard padded base64, exactly 32 bytes.
`local-address` is mandatory (at most eight IP addresses/prefixes).
Optional `preshared-key`, `allowed-ips` (default `0.0.0.0/0,::/0`, at most 128),
`mtu` (1280–9000, default 1420), `keepalive` (0–65535 seconds) and `dns`
(at most eight literal IP addresses). DNS requests for destinations use these
resolvers inside WireGuard; no system DNS fallback is provided for them.
Peer endpoint bootstrap uses the host's normal protected resolver before
routes change. Unknown options, nonzero reserved-byte extensions and TCP
detours are not accepted. Outer transport is UDP; the peer must be reachable
over UDP. TUN/local proxies/SDK routing can use the resulting TCP/UDP streams.

Before returning a new client, the engine waits for authenticated WireGuard
key establishment. It tries IPv4 endpoints first and reserves setup time for
remaining alternatives, with at most two seconds on an endpoint when others
remain. Handshakes are sequential: simultaneous sockets using the same static
key can otherwise make the server roam to a losing socket. Failed attempts are
closed and joined. Destination TCP connections still use the 250 ms successful-
family race. Invalid peer keys or PSKs time out;
`Device.Up` alone is never treated as proof of connectivity.

Server routing profile:

```json
{
  "outbounds": [{"tag": "direct", "uri": "direct://"}],
  "final": "direct",
  "inbounds": [{
    "protocol": "wireguard", "listen": "127.0.0.1:51820",
    "wireguard": {
      "private_key": "<server-private-key-base64>",
      "mtu": 1420,
      "peers": [{"public_key": "<client-public-key-base64>",
                 "allowed_ips": ["10.71.0.2/32", "fd71::2/128"]}]
    }
  }]
}
```

Run with `--config server.json --no-socks`. At most 128 configured peers,
32 allowed prefixes per peer; optional `preshared_key` is supported. WireGuard
authenticates/decrypts packets and enforces the peer's source prefixes before
they reach the native core TCP/UDP forwarder. Each resulting flow uses the
engine's shared connection limit, destination routing and socket protection.
Authenticated server inbounds can relay loopback destinations, like other
proxy servers; the public OS/mobile TUN API retains its existing loopback
packet policy. Configure block/routing rules when destinations need limits.

Clients are created lazily and reuse at most eight active WireGuard devices
inside the broader 64-entry protocol cache. Active devices are never evicted
for a new node. Idle devices retire after 30–45 seconds. Admission failures
are terminal resource errors and do not consume a roster of alternate nodes.
Each device uses two workers per crypto stage, 16 staged packets per peer,
64-entry data/handshake queues, one-packet portable socket batches, a 64-entry
virtual link queue and 64 KiB default / 256 KiB maximum TCP socket windows.
Packet buffers cover the 9000-byte MTU ceiling on Windows, mobile and desktop.
No device or its workers is created when WireGuard is unused.

Every physical UDP socket passes the protection hook before binding. Protection
failure closes any already created family socket and cannot switch to an
unprotected path. Device close joins crypto/event/socket workers and the
virtual stack; server close also joins native forwarding. Component changes
are checksummed in `components/patches/manifest.json` and staged in mobile builds.
They cover worker count/joining, bounded queues/buffers/windows, closed packet
notification handling and release of packet/view references. Encryption and
authentication remain the official implementation's algorithms.

Local acceptance verifies IPv4/IPv6 TCP/UDP payloads, repeated connections,
shared transport reuse, native server forwarding, PSK success/rejection,
wrong peer keys, protection failure, handshake timeout, endpoint IPv4 preference,
encrypted DNS, cache admission and active-owner shutdown. An independent
Python peer implements the published Noise_IK handshake and packet encryption
using cryptography 50.0.2; it passed encrypted TCP and UDP payloads against the
core server and rejected corrupt MACs, unknown identities and source spoofing.
It does not import wireguard-go or the project's framing code. These are local
protocol/ownership results; kernel WireGuard, public nodes and Windows host
route/DNS behavior require separate Internet/platform acceptance.
