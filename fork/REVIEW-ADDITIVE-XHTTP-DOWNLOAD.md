# Additive XHTTP downloadSettings node import — review checkpoint

Base: `feature/tcp-mkcp-additive-review-20261017` after commit `d3fc525c24ef9ef885fd5b775b81a731df45cd68`.

Scope: add bounded downloadSettings input to XHTTP (`xhttp` / `splithttp`) node `extra` only, preserving the four protocols (VLESS, VMess, Trojan, Shadowsocks). Changes are in node-reader integration, a new narrowly validated helper and tests; existing XHTTP dialer, listener, stream builder and original full JSON remain unmodified.

## Connection-only download representation

The `extra.downloadSettings` object must explicitly provide: `address` (ordinary endpoint), `port` (1..65535), `network` (`xhttp` or `splithttp`), and `security` (`none`, `tls`, or `reality`). The optional `xhttpSettings` object admits only `host`, `path`, and `mode`. The optional TLS object admits only client verification metadata (`serverName`, `fingerprint`, `alpn`, `pinnedPeerCertSha256`, `verifyPeerCertByName`, `echConfigList`). The optional REALITY object admits only client connection metadata (`serverName`, `fingerprint`, `publicKey`, `shortId`, `spiderX`, `mldsa65Verify`). Normal full-JSON builders retain final validation and network behavior.

Unknown, duplicate, case-ambiguous, oversized, environment-derived, file-based, arbitrary nested transport, socket and finalmask metadata are rejected. `stream-one` + downloadSettings stays disallowed by the existing XHTTP builder; no fallback or TLS verification bypass is added. Existing XHTTP links without `downloadSettings` keep their original `extra` parsing.

## Three review levels

1. **Source/validator**: Go formatting and isolated Go standard-library test harness with race detection; results from that harness are **not equivalent to full-module tests**.
2. **Config parity**: source-reviewed regression fixtures for all four protocols compare node-generated stream config to explicit complete stream config, URI to versioned JSON-node, legacy VMess JSON share, unchanged existing XHTTP extra, rejection of unsafe nested metadata. Tests are authored; repository-wide execution is **NOT_VERIFIED** pending full dependency-capable CI.
3. **Final only, NOT_VERIFIED**: independent TLS/REALITY XHTTP download peer testing, entire suite on Windows/Linux/macOS, race/vet/build, and additive TCP/mKCP plus later groups evaluated together. No statement of runtime interoperability is made at this checkpoint.

This checkpoint is not a merge into the owner's original branch and is not an application or production deployment.
