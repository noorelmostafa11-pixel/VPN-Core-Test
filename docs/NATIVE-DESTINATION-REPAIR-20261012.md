# Native destination repair — 2026-10-12

The selected VLESS REALITY node succeeded with Xray's HTTP/TLS destination
override but failed on the same IPv6-addressed HTTPS requests with override
disabled, matching the old Go core. Shared bounded destination handling now
passes the hostname to the existing protocol dialer and replays bytes unchanged.
Credentials, URI options and protocol codecs were not replaced.

DNS belongs to the Go core: local and native TCP/UDP use pooled HTTPS through
the node, Cloudflare/Google alternatives, a bounded response cache and reliable
name mappings. IPv4 preference preserves IPv6-only names. ECH/opaque web traffic
retains its IP without a reliable DNS mapping. Non-web ports retain the original
handshake behavior. Dual-family bootstrap uses a 250 ms alternative and closes
losers; one-family dialing has no racing overhead. Windows upstream binding and
bootstrap pinning prevent recursive capture when the host installs TUN routes.

Local validation:

- Race-enabled core/mobile tests, including TLS HTTPS regression controls on
  SOCKS and IPv4/IPv6 native packet paths, DNS fallback/cache/local/native TCP
  and UDP, malformed input, ECH and canceled/failed address-family races.
- 161 independent protocol/carrier tests passed; two optional external-server
  cases skipped. No URI/protocol options were removed.
- Windows v1/v2 transaction fault injection and recovery retry passed.
- Standalone Go 0.5.2 native Windows acceptance on Oracle-Direct-Test-CF and
  Oracle-Direct-Test-2: unelevated headless Chrome used default DNS/QUIC behavior,
  fresh profiles and no proxy/host/IP/TLS override. Cloudflare, example.com and
  Google response bodies passed on both nodes; trace exits matched 84.235.245.14
  and 141.145.149.28. Wintun traffic counters increased.
- Native IPv6-addressed Cloudflare requests with TLS SNI passed on both nodes,
  recovering through IPv4 egress. This does not prove IPv6 WAN connectivity.
  Original physical DNS was restored after both sessions.
- HTTP sniff parsing measured about 0.38 microseconds and 160 bytes/op locally
  on an i7-8550U. Network latency remains dependent on the node/path.

The deleted Windows application was not recreated. The PowerShell launcher
only applies OS policy; forwarding, destination handling and DNS are in Go.
`main` remains separate and unchanged. Private node fixtures/results remain
outside source control. The optional Windows Internet acceptance test accepts
an explicit node library, optionally selected names, and records browser
results/rollback. It contains no fixed provider or node list; matching the
server IP to the trace exit is optional because generic nodes may use separate
egress addresses. The two live nodes above are the extent of local Internet
validation, not proof that every public node or protocol deployment works.
