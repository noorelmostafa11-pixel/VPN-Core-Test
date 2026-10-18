# Current four-protocol scope

The owner changed the project scope on 2026-10-17: remote VPN nodes support
**Shadowsocks (including SS2022), Trojan, VLESS and VMess only**. This supersedes
the earlier plan to port every protocol from the pinned native reference.
Reference revisions remain recorded in [manifest.json](manifest.json).

Local SOCKS/HTTP/mixed/TUN ingress, tunnel forwarding, DNS, routing, direct/block
and loopback remain core services. Remote SOCKS/HTTP clients are removed.
TCP/UDP carriers, WebSocket, HTTP Upgrade, gRPC, XHTTP/HTTP3, standalone HTTP2,
legacy QUIC, mKCP, XDrive, packet masks, TLS and REALITY remain available to the
four protocol families. Their presence is not support for another VPN protocol.

The SSH, Hysteria1/2, WireGuard and MASQUE proxy implementations are excluded.
Hysteria2/MASQUE transports and their dedicated configuration/API hooks are
removed. TUIC, AnyTLS and ShadowTLS are outside the scope, with no port planned.
Shared BBR/Brutal congestion code now lives under the QUIC transport and remains
in use by XHTTP/HTTP3. TUN's platform adapter dependencies do not enable a
WireGuard proxy. QUIC packet camouflage names also do not register VPN proxies.

The shared URI, versioned JSON-node and Go resolver accepts only ss, trojan,
vless and vmess. Full Xray configuration retains local core services but no
removed remote handler. Preserved original protobuf DTOs cannot instantiate
removed HTTP/SOCKS clients. Unknown/removed nodes fail before network activity;
there is no alternate protocol or executable fallback.

## Retained compatibility work

- All 32 classic Shadowsocks method names remain, with exact algorithms, key
  sizes and single-user restrictions for unauthenticated methods. SS2022 remains
  in its original separate handler. See [classic checks](VERIFICATION-CLASSIC.md),
  [AES modes](VERIFICATION-LEGACY-AES.md) and [remaining block ciphers](VERIFICATION-BLOCK-CFB.md).
- VMess legacy body/header additions remain isolated from modern defaults,
  including ignored alterId/AUTO behavior, bounded replay handling and explicit
  inbound weak-body policy. See [body](VERIFICATION-VMESS-BODY.md),
  [header](VERIFICATION-VMESS-LEGACY-HEADER.md) and [preservation](VERIFICATION-PRESERVATION.md).
- Standalone HTTP2/h2c/REALITY and legacy QUIC remain carriers for the four:
  [HTTP2](VERIFICATION-HTTP2.md), [REALITY](VERIFICATION-HTTP2-REALITY.md),
  [QUIC](VERIFICATION-LEGACY-QUIC.md), [typed headers](VERIFICATION-QUIC-TYPED-HEADERS.md).
- URI, versioned node JSON and Go use [one selection point](VERIFICATION-IN-PATH-ADDONS.md).

Current checks and limitations are recorded in
[the scope verification](VERIFICATION-FOUR-PROTOCOL-SCOPE.md). Earlier verification
records describe their historical revisions; they do not enable removed proxies.
The remaining work is compatibility/import/SDK validation within the four
families, not restoration of the cancelled protocol migration backlog.

The 2026-10-18 [reviewed transport/import additions](VERIFICATION-ADDITIVE-TRANSPORT-MERGE.md)
cover TCP HTTP camouflage, mKCP metadata, WS/HTTPUpgrade/HTTP2/gRPC settings,
separate XHTTP download settings, bounded legacy QUIC congestion/flow settings,
and explicit subscription formats. The supported v2ray-plugin WS subset requires
`mux=0`; default multiplexed plugin framing is rejected. The review record also
documents reproduced transport lifecycle defects and their focused corrections.
