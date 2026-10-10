# Go-native TUN migration — isolated candidate, not a production release

Branch: `feature/native-tun-go-core`
Parent: `cb86530eba8a83fcc6aad7c1083bdcd5643304a9`
Stable 0.4.11 / `main` / original Windows and Android applications are untouched.

## Architecture implemented in this branch

The experimental `tls-provider/nativego` is a pure Go TUN packet/data
path. It uses the repository's pinned gVisor stack (TCP/UDP/IPv4/IPv6),
Go workers, a Go protocol engine, and protected Go carrier sockets.
The new package uses no C++ protocol engine or CGO API per packet. The
existing C++ product path is preserved for safe rollback.

The embedding host remains responsible for real interface addresses, routes,
link-local DNS policy, protected bootstrap resolution and fail-closed firewall.
Go-only processing **does not replace an operating system kill switch**.
The new code must never use an unprotected direct carrier fallback.

### Functional coverage

| Item | Go candidate |
| --- | --- |
| gVisor TCP/UDP forwarders, IPv4/IPv6 | Implemented; protected packet-device ownership |
| TCP raw VLESS with encryption=none and no Vision | Implemented with strict TLS or REALITY |
| TCP raw Trojan | Implemented with authenticated TLS |
| TCP raw classic Shadowsocks AEAD | Implemented for AES-128/192/256-GCM and ChaCha20-IETF-Poly1305 |
| DNS | Owned IPv4/IPv6 DNS port 53 via DoH through the selected encrypted node |
| Non-DNS UDP | Go VLESS/Trojan UDP over authenticated raw TLS/REALITY carrier with strict reply destination; classic Shadowsocks UDP is not yet implemented |
| REALITY | Go uTLS/X25519 authenticated source-derived handshake for raw VLESS; no Vision |
| Node URIs | Strict subset VLESS/Trojan and SIP002 classic AEAD Shadowsocks; rejects unsupported options, insecure TLS, unknown transports and ambiguous query parameters |
| Linux TUN | Borrowed FD or Go-created `/dev/net/tun`; Go Linux CLI with protected SO_MARK/SO_BINDTODEVICE carrier |
| Windows Wintun | Go-only verified pinned-DLL packet adapter; no complete Go-owned WFP/routes/DNS host yet |
| Android | Go borrowed-FD support, ARM cross-build; no native app/VpnService replacement or physical-phone acceptance |

For the Linux CLI, the `-policy-ready` flag is an **embedding contract**,
not a verification of installed nftables rules. A privileged host must
install and verify its fail-closed nftables/route/DNS policy independently.
The CLI requires a real underlay interface, an allowed nonzero socket mark,
a pre-resolved endpoint IP (for hostname nodes), and a private URI or JSON
file. It does not alter routes or trust an insecure certificate.

### Verification so far

- Go-only Linux and Windows unit/race/build jobs and Windows/Android cross
  compilation in `.github/workflows/native-go-candidate.yml`.
- Strict TLS VLESS/Trojan controlled encrypted peers with valid certificates;
  parallel encrypted TCP and UDP framing; Shadowsocks AEAD tamper rejection.
- Tests of invalid REALITY public-key/short-ID inputs and rejection of
  unsupported Vision modes. This does not prove public REALITY nodes connect.
- Repeated in-memory gVisor lifecycle and a complete in-memory IPv4 UDP
  TUN-packet -> Go DNS -> return-packet integration test.
- Linux real `/dev/net/tun` DNS packet acceptance added and gated behind a
  dedicated network namespace and `VPN_NATIVE_GO_PRIVILEGED_TEST=1`.
  Consult the matching commit's GitHub Actions report for actual runtime
  status; do not infer success merely from existence of the test.

All these tests use controlled/local endpoints and cannot establish true
public Internet connectivity on a user's Windows or Android machine.

## Missing before replacement or production use

1. Public Internet Full TUN acceptance on actual Windows, Linux and Android;
   capture DNS/TCP/UDP/IPv6 routing, real website certificate verification,
   app browsing, lifecycle, crash fail-close, system DNS and leakage evidence.
2. Go-only Windows WFP/routes/DNS owner and Android VpnService host integration,
   including verified socket protection and always-on/lockdown behavior.
3. Remaining protocol and transport parity against stable 0.4.11:
   VMess, SS2022/legacy stream ciphers, Shadowsocks UDP, Vision, WebSocket,
   XHTTP/HTTPupgrade/gRPC/QUIC/mKCP and any other supported original URI.
4. Full unchanged URI parser/identity comparison with original stable
   inventories, controlled real-node regression and verified output hashes.
5. Resource, throughput, RTT and security approval **after Internet works**.

Keep unsupported features fail-closed rather than changing certificate
verification, replacing a node URI or silently dropping to plaintext/TLS.

## Build and test (Go 1.27.1; from tls-provider/)

```sh
go test -race -count=1 -v -tags=netstack -mod=vendor ./nativego
go vet -tags=netstack -mod=vendor ./nativego
CGO_ENABLED=0 go build -tags=netstack -mod=vendor ./nativego
CGO_ENABLED=0 go build -tags=netstack -mod=vendor ./cmd/nativego-linux
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags=netstack -mod=vendor ./nativego
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -tags=netstack -mod=vendor ./nativego
```

The privileged Linux acceptance must be run only in a throwaway network
namespace (as CI does). Do not run elevated route/firewall experiments against
an installed production VPN or a machine without independent network recovery.
