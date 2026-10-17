# Scheduled VPN Core engineering: immediate round 1

Baseline: 51030322ed3a6687d0dc20568a82fcccd973b155
Branch: feature/tcp-mkcp-additive-review-20261017

## Implemented
Accept the optional query name `headers` on WebSocket and HTTPUpgrade connections only. Both use the existing header parser, including reserved handshake-header rejection, header length/character limits and alias conflict rejection. No transport implementation, security policy or established default is changed. URI and versioned JSON-node import are supported with the same string parameter. VMess legacy JSON share envelopes can pass `headers` as an escaped JSON string; a raw nested JSON object is **not added in this round**.

## Tests
New four-protocol (VLESS, VMess, Trojan, Shadowsocks) configuration-selection fixtures plus rejection fixtures for unrelated networks, reserved header names and conflicting aliases. Full repository Go 1.27.1 race/vet/build and independent wire/platform validation remain **NOT_VERIFIED** and are deferred to the agreed final test level. No workflow was dispatched. No main or original owner branch changes.

The task is additive to the four retained protocols only; no generic SIP003 launcher, QUIC fingerprint impersonation or new remote VPN protocol is introduced.
