# Hourly additive review: headers alias import regression

Base HEAD: 42f1a116261193beec966bb583a7071ade3df662
Branch: feature/tcp-mkcp-additive-review-20261017
Date: 2026-10-17

## Added verification coverage
- VMess legacy JSON share envelopes: existing escaped-string `headers` alias works on WebSocket and HTTPUpgrade, including outbound Build.
- VMess JSON rejection cases: reserved Host/Connection, case-insensitive duplicate header keys, and headers on unrelated TCP transport.
- Versioned JSON node descriptions: same selected transport protobuf as URI import for VLESS, VMess, Trojan and Shadowsocks, on both WS and HTTPUpgrade.

No production transport/parser code is changed in this round. A proposed additional VMess raw-object `headers` import was inspected but its source write was blocked by connector safety checks; it remains **UNIMPLEMENTED**. The existing raw-object aliases `wsHeaders` and `httpUpgradeHeaders` are unchanged. Do not present this test-only commit as a new wire capability.

## Verification
Level 1: inspected `infra/conf/node_uri.go`, `node_transport.go`, `node_advanced_transport.go`, `node_xhttp_download.go`, and existing tests. Level 2: authored repository regression fixtures; full Xray test execution **NOT_VERIFIED** (Go 1.27.1 unavailable; git clone DNS lookup failed). An isolated Go 1.23.2 copied-parser/header-helper harness passed `go test -race -count=1 ./...` and `go vet ./...`; this is NOT the full project or independent wire proof. Level 3 remains deferred.

The requested `00-ENGINEERING-RULES.md`, `01-SYSTEM-ARCHITECTURE.md`, and `08-UNVERIFIED-AND-OPEN-POINTS.md` were not found in the complete branch tree or Library title search. Available `AGENTS.md`, `fork/VERIFICATION-PRESERVATION.md`, and `fork/REVIEW-REMAINING-GAPS-AND-TEST-GATE.md` were reviewed instead. No CI dispatch, PR, merge, main/owner-branch change or release.
