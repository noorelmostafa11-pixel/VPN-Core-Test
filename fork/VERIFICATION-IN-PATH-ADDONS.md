# Shared node selection for the four supported protocols

The owner's 2026-10-17 scope change limits remote nodes to Shadowsocks, Trojan,
VLESS and VMess. This document describes the retained input architecture;
[current scope verification](VERIFICATION-FOUR-PROTOCOL-SCOPE.md) supersedes the
former all-protocol migration inventory.

URI syntax is parsed by DescribeNodeURI; versioned JSON uses
DecodeNodeDescription; Go supplies NodeDescription directly. All three reach
conf.ResolveNode, which validates known protocol/transport/security metadata,
selects required registered capabilities and prepares the ordinary Xray
configuration. One core lifecycle then owns handlers, routing and transports.
Selection performs no network I/O, protocol probing, byte replay or fallback.

Accepted remote schemes are ss, trojan, vless and vmess. SS2022 is a Shadowsocks
cipher selection. Descriptions use id for VLESS/VMess, method/password for SS,
and password for Trojan. Mixed credentials, unknown protocols, conflicting
aliases, unsupported transports/security combinations and arbitrary local file
imports reject. The label and credential bytes are never included in resolver
errors. Full original JSON/protobuf bypasses this description resolver; retained
protocol defaults, ignored fields, TLS/REALITY verification and routing keep
their meaning. The intentionally removed remote protocols no longer register.

| Connection metadata | Responsibility |
| --- | --- |
| Modern VMess/VLESS, Trojan, original SS methods | Original handler |
| VMess alterId1..64 | Bounded legacy header/replay addition |
| VMess CFB/NONE/ZERO body | Explicit internal body selector; ZERO TCP only |
| Added classic SS method | Matching cipher/key/IV implementation |
| Classic SS node input | Retained server-first node contract; full JSON default unchanged |
| SS2022 method | Original SS2022 handler; no classic server-first selector |
| HTTP/H2/H2C | Separate HTTP2 carrier with TLS/REALITY/h2c rules |
| QUIC | Separate legacy carrier, including historical typed packet headers |

NodeSelection.Addons reports those decisions; it is not a feature toggle or a
retry list. Original low-level legacy settings remain an explicit full-config
representation; a node supplies sufficient metadata and the resolver generates
them automatically.

CLI .uri/.node file detection, explicit format selection and normal merging
remain available in the ordinary distribution. Go entry points are
core.StartInstance("uri", data), core.StartInstance("node", data),
conf.ParseNodeURI, conf.ParseNodeJSON and conf.ResolveNode followed by the usual
conf.Config.Build/core.New lifecycle. Default directory discovery is unchanged.
Application/SDK ABI and foreign-platform runtime remain separate acceptance.
