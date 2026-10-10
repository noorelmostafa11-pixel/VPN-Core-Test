# Native TUN DNS acceptance — 2026-10-10

The Windows handoff baseline can pass authenticated HTTPS through the native
packet path while its IPv6 UDP DNS fails. DNS availability must therefore be
independent of a node's UDP support and IPv6 egress. Native now serves its owned
DNS endpoints through verified HTTPS over the existing C++ proxy protocol.
This is a general DNS path; no node URI, server IP, SNI or credential is rewritten.

## Baselines and evidence

- Stable source: `90a1853114de3e4bcb3deed6747801c10bc5b370` (0.4.11).
- Original Native source: `f41c61db54b68906f0ff6bcaa782b8c12b4ffe5a`.
- Public inventory: `VPN-Nodes@7da6036d205691e3a0bf4a2f2ca4c3bd887b2e46`,
  generated 2026-10-10T01:21:55Z. Original Git blob hashes verified on download.
- Local reports contain hashes and failure codes, without URIs or credentials.
  Runtime tests use temporary config files; published node inventories and local
  evidence are excluded from Git.

Observed on the two local VLESS/REALITY/Vision nodes, with unchanged original URIs:

| Test | Original Native | DNS implementation |
|---|---|---|
| IP-destination HTTPS, valid certificate and complete example.com body | PASS | PASS |
| Direct 1.1.1.1 HTTPS | PASS | PASS |
| IPv4 UDP DNS | PASS | PASS |
| IPv6 UDP DNS | FAIL, `UDP_TUNNEL_CLOSED` | PASS |

A real Windows Full TUN run of the original baseline also passed direct IPv4
HTTPS and IPv4 DNS. Its IPv6 DNS failed. A separate website returned HTTP 403;
that is a reachable HTTP response, not evidence of lost Internet access.
The historical cause of every previously reported TCP reset or outage has **not**
been established by these tests. The confirmed DNS dependency is addressed here.

The modified Windows Full TUN passed certificate-verified HTTPS, system DNS
HTTPS and UDP DNS from both address families. Graceful exit returned zero,
removed the owned WFP provider, and restored the original physical route/DNS
fingerprint. Additional final-build acceptance includes TCP DNS, a 1 MiB
verified download and explicit recovery after a deliberately crashed test owner.
These final results must be read from the matching build report, not assumed from
this preliminary source report.

## Implementation

- Owned resolver addresses: `198.18.0.53` and `fd71:5650::53`, UDP/TCP port 53.
  Windows and Linux own explicit host routes to these endpoints, in addition to
  the existing full-tunnel routes. Android's experimental host uses the same
  resolver addresses inside its VPN routes.
- Both addresses serve actual DNS records. There is no fake address allocation,
  sniffing or destination/SNI substitution.
- DNS goes to `https://cloudflare-dns.com/dns-query` through a
  `PacketProtocolStream` using the selected node's original configuration.
  The resolver TLS uses system trust and hostname validation independently of
  the node's TLS configuration. There is no direct physical DNS fallback.
- The existing provider TLS and HTTP body parser are reused. The shared packet
  protocol stream was extracted into a header so DNS does not duplicate the
  encrypted transport implementation. No SOCKS listener is added to Native.
- TCP DNS accepts fragmented and pipelined length-prefixed queries. Large UDP
  responses set TC and retain the question so clients retry over TCP at the
  same owned resolver. Upstream failures produce SERVFAIL; cancellation
  propagates to the existing stop/join path.
- DNS has bounded input/output and deadline budgets. Idle UDP resolver flows
  release their worker after two seconds. DNS workers wait for packet events
  rather than allocating a 1 ms provider polling timer between requests.
- Ordinary TCP/UDP destinations and the parser retain their previous behavior.
  The C ABI and TUN options layout remain unchanged.
- Failure events now include CONNECT/TLS/TRANSPORT/PROTOCOL/RELAY stage,
  TCP/UDP, destination family/port and original OS status. They omit destination
  addresses, hostnames, query contents, UUIDs and keys. WFP/nft fail-closed policy
  and ownership-based recovery remain enabled.

## Verification completed before final packaging

- Windows build with Go 1.27.1 and GCC 16.2.0: component ABI and self-tests passed.
- 17 encrypted/bootstrap/packet-ownership test methods: 16 passed; one Linux-only
  policy syntax method skipped on Windows. Subcases cover VLESS, Trojan, VMess,
  Shadowsocks, TLS/REALITY, raw/WebSocket/HTTP upgrade/gRPC/XHTTP and both families.
- DNS boundaries: truncated requests, invalid pointers, TC fallback, SERVFAIL,
  owned endpoint matching and partial TCP EOF passed without network I/O.
- All 5,075 public inspection rows exactly match stable 0.4.11. Supported count
  remains 5,073; the same two configurations remain unsupported. This is parser
  and identity evidence, **not** a claim that 5,073 Internet connections passed.
- Twenty public nodes were attempted with stable controls. Six qualified:
  two Shadowsocks, one Trojan, one VLESS and two VMess. All six passed native
  HTTPS, IPv4/IPv6 DNS, pipelined TCP DNS and a complete 1 MiB HTTPS download.
  The download SHA256 matched its stable control where that control succeeded.
  Nodes failing the stable control were not counted as Native acceptance.
- The in-memory packet Internet probe does not exercise OS routing or WFP.
  Windows Full TUN evidence is recorded separately by the elevated acceptance
  runner. The original installed stable Core and original backups were untouched.

## Reproduction

Build with `scripts/Build.py --target windows --experimental-netstack`.
Run controlled regressions with `test_native_dns`, `test_native_tun_encrypted`,
`test_native_tun_bootstrap` and `test_netstack_abi`, setting `VPN_NATIVE_BUILD`
and `VPN_CORE_TEST_BINARY` to the matching build.

`scripts/Test-Native-Internet.py` compares stable SOCKS against a loopback test
packet gateway. It takes build paths, a local URI inventory, and an output
folder; it creates no adapter or OS policy. `--qualified-only --download` tests
Internet traffic only after a stable control qualifies the node.

`scripts/Test-Windows-Native-Internet.py` requires Administrator and tests real
Full TUN. It refuses an existing native/tun2socks process or persistent owned
WFP guard. Use it on an isolated machine or VM with independent recovery access.
It records safe teardown and network restoration. `--crash-recovery` explicitly
crashes its own test process and verifies retained protection plus owned recovery;
it does not target the installed app or any unrelated process.

## Limits and next coverage

This sample does not certify every public/private node, production throughput,
large-scale concurrency or Android/Linux Internet behavior. Windows acceptance
and the multi-platform CI results must be pinned to the final source/build hash.
The historical 10054 reports remain distinct from the DNS evidence above.
The existing 8 MiB CI performance comparison remains useful, with its synthetic
scope, and is not substituted for the real HTTPS/download checks.

Protocol references: [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484),
[Cloudflare DoH wire format](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/).
