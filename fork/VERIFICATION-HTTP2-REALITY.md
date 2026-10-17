# Add standalone HTTP/2 with REALITY

Date: 2026-10-17. Parent: `9b4f7f832ebe9d86b9f5e9b37994501be5e80958`.
Pinned upstream and main comparison revisions remain in `manifest.json`.

## Additional path, not an original-path replacement

`http`/`h2`/`http2` with `security: reality` now selects the existing REALITY
authentication and fingerprint implementation, followed by the separate HTTP/2
carrier. Node URI metadata selects this pairing automatically; no enable switch
is added. `h2c` still means cleartext and rejects TLS/REALITY. Missing or unknown
security settings never become plaintext. Proxy payloads are not replayed or
used to probe another protocol after a failure.

The original RAW/TCP, XHTTP and gRPC REALITY code, normal TLS implementation,
proxy implementations, original JSON field semantics and owner stability fixes
are unchanged. Only the builder's added-transport allowlist and the fork's
standalone HTTP/2 transport gain this pairing. No dependency or protobuf change.

HTTP/2 still uses its exact host/path/query/method checks and unmodified full-
duplex request/response bodies. REALITY must authenticate before HTTP/2 starts.
The server exposes its actual TLS version, cipher, completion, SNI and ALPN to
the HTTP/2 engine; it does not pretend the connection is cleartext.

## REALITY and ALPN are not ordinary TLS

Pinned `github.com/xtls/reality` revision `8cdf7bf9c7f0` deliberately skips its
normal `processClientHello` ALPN selection and sends an empty selected protocol
for authenticated connections. This is also why upstream XHTTP selects H2 from
REALITY settings rather than from a negotiated ALPN value. Requiring ordinary
TLS's mandatory `h2` value here rejects legitimate authenticated REALITY.

The added pairing therefore permits authenticated empty ALPN with an explicit
HTTP/2 selection and requires the H2 preface/frames. It also accepts actual `h2`
from other REALITY implementations. Any explicit non-H2 ALPN is rejected before
application data. It never invents an `h2` negotiation. Ordinary TLS retains its
existing mandatory negotiated-`h2` guard and certificate/pin validation.

The pinned server API requires its existing target record detector, as used by
RAW. This detector and its global caches/probes are inherited, not redesigned
or claimed to be listener-owned. The new listener does own accepted sockets,
H2 streams and handshake targets: per-handshake target I/O is bounded to four
seconds and listener cancellation closes a silent target so workers can join.
This target bound affects only the new pairing, not original REALITY paths.
The listener waits at most eight seconds for actual target-detector completion
before accepting its first H2 handshake. Failure/cancellation releases the
listening socket; an application connection is never used as a warmup retry.

## Local tests and independent checks

- Added configuration test first failed because the old H2 guard rejected
  REALITY. URI and JSON now select the pairing while `h2c`/missing/unknown
  security guards remain active. Network and method aliases are covered.
- Both transport roles exchange server-first greetings, fragmented exact
  120003-byte uploads/downloads and upload half-close with independent peers
  built directly from the pinned REALITY API and x/net HTTP/2, not the fork
  transport handler at both ends.
- A separate stdlib X25519/HKDF/AES-GCM/Ed25519/HMAC oracle authenticates the
  actual captured ClientHello and negotiates real `h2` or `http/1.1`. The first
  succeeds; the latter is rejected without sending an application request.
- Wrong public key, short ID and SNI are rejected. Application requests do not
  reach the local fallback target. An authenticated HTTP/1.1 preface is rejected
  without invoking the proxy handler. Normal TLS bad-pin/ALPN tests stay active.
- Cancellation tests prove a client really emitted a stalled ClientHello and
  that a listener really dialed a silent target before cancellation. Workers
  join and owned connection/stream maps empty; no injected fault is assumed.
- A cold listener's first independent connection succeeds without test-side
  prewarming. Startup cancellation is tested after an actual detector dial, and
  the same listening port can immediately be rebound.
- VLESS core-to-core with a separate server-first TCP echo passes through JSON
  and URI inputs for both added H2/REALITY and original RAW/REALITY. The existing
  h2c JSON/URI cases remain active too. No private node or key is used.

## Validation record

Final-source environment: Go1.27.1, Windows/amd64, GCC16.2 for race detection.

- New pairing/guard/lifecycle/first-connection tests repeated five times with
  race detection: PASS H2 34.983s and configuration 9.517s.
- Vet: PASS all affected configuration/core/main/HTTP2/internet/TCP/gRPC/XHTTP
  packages, exit0. No whole-repository vet claim.
- Compilation: PASS Windows/amd64, Linux/amd64 and Darwin/arm64, CGO0,
  `-trimpath -ldflags='-s -w'`. Only Windows is executed; cross-builds are not
  foreign-platform runtime acceptance. No mobile/package/release jobs.
- The final Windows CLI accepts the synthetic H2/REALITY `.uri` input with the
  ordinary config check: `Configuration OK`, exit0. It remains outside Git as
  `xray-fork-http2-reality-final-20261017.exe`,35264000 bytes,
  SHA256 `d0c2515d3d106931f68c87be9b65c26523eeb6a71d31aa1176dcfe7c4fc2a01f`.
  Build metadata is `9b4f7f8-dirty`, not a mislabeled future clean commit.
  No binary-size reduction is claimed.

- Full affected packages: PASS race conf12.763s,serial10.043s,main8.101s,
  core121.705s,HTTP2 16.470s,internet5.736s,gRPC6.947s,XHTTP8.604s; TCP
  compiled with no tests on Windows. This is not a full-repository test command.
- Exact shared original-behavior fixture on pinned upstream: PASS race16.307s;
  the fork runs the same unchanged fixture in its full configuration package.

-20 unchanged original scenarios: PASS race150.839s, covering modern VMess,
  Shadowsocks, SOCKS TCP/UDP/Mux/routing and VLESS/TLS/Vision/REALITY. The
  upstream REALITY scenario retains its public target; this is not a general
  Internet-acceptance or full-TLS-suite claim. No KCP/ECH scenario selected.

Original shared fixture remains byte-identical on the pinned baseline and fork:
SHA256 `f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.
1194 Go/protobuf/module paths have source fingerprint
`4ad5de9b8bc08807553ad7b0bccee2f1071cd41a256a703b56b06da31c36f668`.

Retained local failures are not hidden: the first implementation incorrectly
required ordinary TLS ALPN from pinned REALITY. A subsequent new fixture
incorrectly checked incoming Go Request.URL.Scheme, which Go's server leaves
empty; it now checks Request.TLS, which x/net sets only for the https pseudo-
scheme and an actual secure state. The pinned API's SNI export was verified
directly. The stdlib oracle initially replaced the parsed signature-scheme
slice rather than updating its backing entry, so Go rejected Ed25519; the
oracle now applies REALITY's Ed25519 rule only after authenticating the hello.
No existing assertion, deadline or original implementation was weakened. The
new fixture assumptions were corrected and explicit non-H2 ALPN remains tested.
Final review also separated cold-listener startup from already-warm fixtures:
the added listener waits for the existing detector before starting its four-
second handshake budget. Full affected, repeated, build and scenario checks
are rerun on that final source; earlier successful runs remain intermediate.

Evidence stays outside Git: `xray-http2-reality-before`, `first-runtime`,
`authenticated-preface`, `oracles`, `expanded`, `state-diagnostic`, `final-focused`,
`repeated`, `affected-race`, `original-baseline`, `original-scenarios`, `vet`,
`build` and `cli` logs. The original external ECH failure is unchanged, not fixed
or relabeled green. Local synthetic/configuration/race evidence is not Internet,
private-node, foreign-OS runtime, main-wire parity or application/mobile SDK
acceptance. No workflow/check/wire runner is changed, run or monitored.

The definitive final-source records are `final-affected`,
`final-source-repeated`, `final-scenarios`, `final-build`, `final-cli`,
`final-crossbuild` and `final-vet-result.txt`, with the same private prefix.
The unchanged fixture's `original-baseline` log remains applicable. Only
documentation was edited after final-source tests and builds.
