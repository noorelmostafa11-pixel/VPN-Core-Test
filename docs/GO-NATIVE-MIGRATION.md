# Native TUN Go-native migration — candidate, NOT a production core

Branch: feature/native-tun-go-core
Parent: cb86530eba8a83fcc6aad7c1083bdcd5643304a9
This branch does not modify stable main, stable ABI2, or the existing Windows/Android applications.

## What is implemented in this migration increment

The new Go package, tls-provider/nativego, uses the pinned in-repository
gVisor source for TCP/UDP/IPv4/IPv6 and communicates directly with an entirely
Go-owned encrypted transport. There are no C++ or CGO calls in this new
package. Packet-device ownership and routing/firewall setup remain the
responsibility of the host. The existing ABI and original C++ path remain
untouched so this work is completely opt-in.

* TCP: gVisor TCP forwarder -> Go relay -> authenticated Go TLS ->
  **raw TLS VLESS (encryption=none, flow empty)** or
  **raw TLS Trojan** -> remote. Strict SSL certificate/hostname checks.
* DNS: Owned VPN DNS endpoints 198.18.0.53 and fd71:5650::53,
  TCP length-framed and UDP DNS, tunneled DoH to 1.1.1.1:443 with
  verified cloudflare-dns.com certificate and no physical fallback.
* TCP/UDP ingress: bounded gVisor link ring, bounded concurrent flows,
  source packet copies before the device read returns, cleanup on stop.
* Node connections require an injected protected underlay dialer.
  No direct network dial is permitted by the library.

## Hard gates and missing work — DO NOT SHIP

This is only the first implementation slice, not a complete migration:

- A Go-only Windows Wintun packet adapter and Linux/Android borrowed-FD adapter
  are present. Windows adapter build is verified, not its physical-device behavior.
  Complete Windows WFP/routes/DNS ownership, Android VpnService lifecycle
  integration and Linux firewall/route-owning host remain unimplemented.
- No Go-native VMess, Shadowsocks, REALITY, Vision, WebSocket, XHTTP,
  gRPC, QUIC, mKCP or alternate protocol transports yet.
- No generic UDP proxy relay yet. Only the dedicated owned DNS UDP
  endpoints are served; other UDP destinations fail closed.
- No final live-node compatibility against stable 0.4.11 and
  no true Windows/Android device tests of the new Go candidate.
- Linux race tests, Windows package tests, Windows/Android cross-builds,
  repeated gVisor lifecycle, framing, and a controlled authenticated TLS
  VLESS/Trojan peer passed in GitHub Actions. These do not certify Internet
  access, kill-switch behavior, release safety or production performance.
- Config currently uses an explicit Go Node struct; no arbitrary
  original URI should be silently rewritten or downgraded.

Before any application integration the feature must support the existing
protocol/URI coverage, run physical OS integration and security gates and
be proven to return genuine public Internet traffic. Do not switch production
to this candidate or remove existing C++ until those gates pass.

## Tests

Run with the pinned Go 1.27.1 toolchain:

    cd tls-provider
    go test -v -tags=netstack -mod=vendor ./nativego
    go vet -tags=netstack -mod=vendor ./nativego
    CGO_ENABLED=0 go build -tags=netstack -mod=vendor ./nativego

These commands do not configure interfaces or modify host networking.
