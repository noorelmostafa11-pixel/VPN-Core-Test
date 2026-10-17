# Additive TCP/mKCP node-transport review checkpoint

Branch base: VPN-Core-Test feature/xray-custom-core commit cdc8e0cc3cd6d12a748f0b128aec316f1e74c642 (2026-10-17).
Scope: four remote protocols only; node URI/NodeDescription input only; original JSON/protobuf and transport runtime are not changed.

Level 1 — source structure and parsing: new helper passed local Go syntax/parser inspection, and four standalone stub-based Go tests passed with -race on Go 1.23.2 Linux/amd64. The standalone harness is not a full-module test.

Level 2 — semantic compatibility: new tests compare the selected TCP HTTP header and mKCP settings/finalmask with explicit equivalents for VLESS, VMess, Trojan and classic Shadowsocks. Tests also assert unchanged no-metadata defaults, legacy VMess JSON-share import, and rejection of invalid metadata. These repository tests are authored but **not yet executed**.

Level 3 — actual interoperability and platform acceptance: **NOT VERIFIED**. Before merging into feature/xray-custom-core, execute affected package tests on Go 1.27.1, compare against the pinned upstream behavior, run independent mKCP header/seed wire fixtures, and pass the complete manual Windows/Linux/macOS validation. Do not infer third-party mKCP legacy-wire parity merely from a finalmask configuration match.

No automatic workflow dispatch, application/mobile release, external live node claim, or change to the four existing remote protocol implementations is part of this draft.
