# VPN-Core-Test: four-protocol Xray core

This branch starts from XTLS/Xray-core v26.10.10, commit
701af60772cda123492f86e383e1fdba066614a9. Upstream history, module path,
attribution and MPL-2.0 license are preserved. Core changes and new executable
tools use Go. Main, stable releases, owner README and private material remain
outside this change.

The owner changed the project scope on 2026-10-17. Remote VPN nodes support
**Shadowsocks (including SS2022), Trojan, VLESS and VMess only**.
[Current scope and verification](fork/VERIFICATION-FOUR-PROTOCOL-SCOPE.md).

Local SOCKS/HTTP/mixed/TUN and tunnel ingress, DNS, routing, direct/block and
loopback remain services for those four. HTTP/SOCKS remote client handlers are
removed. SSH, Hysteria1/2, WireGuard and MASQUE proxies are excluded. Other VPN
protocols will not be ported under the cancelled migration backlog.

The four retain their existing transports and security, including TCP/UDP,
WebSocket, HTTP Upgrade, gRPC, XHTTP/HTTP3, standalone HTTP2/h2c/REALITY, legacy
QUIC, mKCP, XDrive, packet masks, TLS and REALITY. Shared QUIC congestion control
is retained under transport/internet/quic/congestion. Platform TUN dependencies
and packet camouflage names do not register additional VPN proxies.

URI, versioned JSON-node and Go descriptions share conf.ResolveNode before the
ordinary Xray configuration/routing/lifecycle. Only ss, trojan, vless and vmess
are accepted remote schemes. There are no per-feature activation switches,
protocol guesses, alternate engines or application-byte retries.
[Input architecture](fork/VERIFICATION-IN-PATH-ADDONS.md).

Retained additions include all 32 classic Shadowsocks method names, isolated
VMess legacy header/body compatibility, standalone HTTP2 and legacy QUIC with
historical protobuf headers. Original defaults, ignored fields, TLS/REALITY
verification and the owner's stability fixes remain protected within the four
families. [Retained inventory](fork/COMPARISON.md) and
[original-behavior baseline](fork/VERIFICATION-PRESERVATION.md).

Tests/build results are scoped evidence, not Internet/private-node acceptance,
foreign-platform runtime or application/SDK ABI acceptance. The existing manual
compatibility workflow remains owner-dispatched; this change does not modify,
dispatch or monitor workflows. [Compatibility workflow](fork/COMPATIBILITY-CHECK.md).

## Build

Use the Go version required by go.mod:

```text
go build -trimpath -ldflags="-s -w" -o xray ./main
```

[Branch engineering rules](AGENTS.md) record the current four-protocol scope.

## Per-target packaging

The owner's existing Go-only packaging utility and verified asset manifest are
preserved. It builds the selected target from this checkout; see
[PACKAGING.md](PACKAGING.md). No package or asset download is run by this scope
change. Packaging, CLI cross-builds and target runtime remain separate checks.
