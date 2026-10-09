# F2 / F5 follow-up — 2026-10-09

Reviewed base: `5e0c34a78bfad38fa818569bd0c60c7a4badd1f1` in
`noorelmostafa11-pixel/VPN-Core-Test`.

## F2: REALITY upgrade authority

`src/http.hpp` now applies the existing absent-Host TLS-name fallback to REALITY
as well. WebSocket and HTTP-upgrade keep the order explicit Host, TLS/SNI name,
endpoint host. An explicit Host is preserved, endpoint dial ports are not added
to this fallback, and other carriers keep their previous authority rules.

Independent REALITY peers authenticate the session and then parse the actual
upgrade request and exchange application data. Both supported upgrade carriers
cover absent/empty Host, explicit Host, empty SNI fallback, an incorrect explicit
virtual host, and corrupt REALITY authentication. The last two remain rejected.
Vision over either upgrade carrier is still rejected by the existing production
configuration validator; this change does not admit that combination.

## F5: separate sending closure from receiving closure and failure

`Tls` in `src/tls.hpp` now records successful initialization, local sending
closure, and terminal operation failure separately. `SecureStream::write_open`
delegates to that state and the actual provider status. A valid TLS 1.3 peer
close_notify can leave sending open, but a local close_notify or a TLS failure
cannot. TLS 1.2 peer closure disables application writes. Both native version
spellings, TLS1.3 and TLSv1.3, are recognized. Repeated local shutdown is
idempotent; rejected late application writes do not poison remaining reads.

The Go provider separately records local sending closure and serializes Write
with CloseWrite. Direct C ABI writes after local shutdown return -1 before
calling the TLS writer, keeping pending authenticated read data available.
Shutdown failures remain terminal, and a later failure preserves the first
numeric TLS cause. Existing exported C ABI signatures and state codes remain.

The original wrapper reported writing open after local shutdown and after TLS
errors. Direct provider writes already returned failure after CloseWrite, but
also marked the entire session failed, damaging its remaining reading direction.
The new direct-C-ABI wire test exercises that distinction independently of the
C++ guard.

## Executed verification and limits

| Evidence | Result | Limit |
| --- | --- | --- |
| Production parser/transport/TLS component probe against independent Python/OpenSSL and REALITY wire peers | 12 test methods PASS on Linux | No core executable or core package was built |
| TLS 1.3 peer close, local close, final authenticated data, final fragmented WebSocket data/pong/close responses, and direct C ABI late-write rejection | PASS with provider and Linux native adapters where applicable | Direct C ABI test uses the provider |
| TLS 1.2 peer/local close and WebSocket final-data preservation without late application writes | PASS with both Linux adapters | Not a Windows-native Schannel wire observation |
| Corrupted protected records under TLS 1.2 and TLS 1.3 | Rejected; writing stays disabled | Controlled local peers, not public nodes |
| Existing plus new Go provider tests, with race detection | 12 PASS, 1 pre-existing external-profile fixture SKIP | The external randomized OpenSSL fixture was not requested |
| Existing Schannel continuation/security-policy component probe | PASS | Synthetic Schannel adapter on Linux |
| Identical new component probe against the published base headers/provider | Reproduced Host and write-state failures | Baseline comparison does not measure node recovery |
| Native Windows execution | NOT_VERIFIED | Registered in the existing manual Core Source Validation workflow; no workflow was dispatched |

The component tests are in `tests/test_tls_write_state.py` and
`tests/tls_write_probe.cpp`; the concurrent shutdown/error checks are in
`tls-provider/write_state_test.go`. Linux validation registers the suite through
`tests/run_validation.py`. Windows validation compiles the component probe beside
the existing provider DLL and runs the same suite through the existing Windows
acceptance step. Synthetic-certificate native-adapter wire cases run only on
Linux; Windows provider and REALITY cases run on Windows validation.

F1, F3, F4 and D1 are retained. Original node URI files, strict curl/HTTPS success
criteria, authentication/certificate checks, core ABI, and DNS resource tests
are unchanged. The TLS provider library and standalone test probes were built
only to execute these component tests. No core rebuild, package build, node run
or workflow dispatch was performed.

Closure semantics: RFC 8446 sections 6.1 and 6.2, and RFC 5246 section 7.2.1:
https://www.rfc-editor.org/rfc/rfc8446#section-6.1
and https://www.rfc-editor.org/rfc/rfc5246#section-7.2.1.
