# D1: independent HTTPS, tunnel and shutdown evidence

`Test Selected Core Against Latest Pre` uses `scripts/Test-Nodes.py`. D1 changes
only its reporting and the network summary. The five proposed core repairs
remain separate work. Protocol implementations, original input URI bytes,
source/ID hashing, shard selection, timeouts, concurrency and verification URL
are unchanged.

The success condition remains **curl exit 0 and HTTP 200–299** over the existing
HTTPS/SOCKS command. Empty 204 responses remain valid. Diagnostic failures do not
promote a failed request to PASS or downgrade a successful request during cleanup.

## Node report: vpn-node-test-v3

| Field | Meaning |
| --- | --- |
| `curl_exit_code` | Original process exit code; null when unavailable. A Python wait timeout does not invent curl exit 28. |
| `curl_reason_code` | Independent curl result, including NOT_STARTED or EXIT_UNAVAILABLE. |
| `curl_http_status`, `http_status` | HTTPS response status from curl, never overwritten with the outer transport status. |
| `curl_error_class` | Bounded category of the curl exit code. |
| `curl_tls_error_class` | Fixed symbolic category inferred from stderr for exit 35; unrecognized text becomes TLS_UNCLASSIFIED. No raw stderr is exported. |
| `first_core_failure` | First complete, valid failure line observed before runner cleanup, excluding cancellation. Log observation order is retained even if the wall clock moves backward. |
| `first_failure` | Primary reported failure with its source and selection basis; this is not proof of a root cause or exact ordering between independent processes. |
| `first_cleanup_core_failure`, `cleanup_core_failures` | Failures observed after the stop boundary, or cancellation events. Stored separately; the list is capped at 16 with a truncation flag and uncapped counts. |
| `last_core_failure` | Last valid failure, for secondary context; cannot replace the original curl result. |
| `core_tunnel_ready` | True when a negotiated event or explicit ready failure is observed before cleanup; false only with explicit non-ready evidence and no ready observation; otherwise null. Readiness does not prove data transfer. |
| `core_exit_code`, `core_stopped_by_runner`, `core_killed_by_runner` | Core process outcome and owned cleanup actions. A runner-issued stop is not mistaken for a spontaneous crash. |
| `curl_*_ms`, `curl_bytes`, `curl_num_connects`, `curl_ssl_verify_result` | Numeric curl timings and counters, when available. Optional metrics do not change the success condition. Redirect/reuse timings cannot be mapped to a core connection ID automatically. |
| `protocol`, `transport`, `security`, `flow`, `fingerprint`, `alpn`, `websocket_early_data` | Whitelisted inspection metadata for grouping. Unknown symbols are OTHER; raw server names, credentials and config values are omitted. |

The cleanup boundary is the log byte offset sampled immediately before stopping
the owned core. Events not completely visible at that boundary are marked as
observed afterward, even if their internal timestamp is earlier. This is an
observation boundary, not a claim about absolute cross-process causality.

Exit 35 remains CURL_35, including when a relay/reset or cancellation diagnostic
appears afterward. It is classified as HTTPS_TLS_OR_TUNNEL rather than assigned
automatically to outer TLS or REALITY. A failure explicitly before readiness,
with no ready observation and a compatible proxy/network exit, may become the
primary outer-tunnel diagnostic; the original curl code is still retained.

The JSON parser accepts complete bounded diagnostic lines, checks connection IDs,
types and integer ranges, and exports only known phases, bounded reason symbols,
numeric statuses and whitelisted negotiated values. Raw log lines, stderr,
certificate contents, URLs, hostnames, original URIs and credentials are not
report fields. Generated native_status values already absent from core events
are not fabricated by D1.

## Shard and aggregate summaries

Each shard separately counts curl reasons, curl-35 subclasses and metadata
groups, first core reasons, cleanup reasons, readiness and failure scopes.
`Summarize-Network.py` aggregates the new fields while retaining complete
15-shard/Pre coverage checks and the old historical comparison. Its schema is
`vpn-network-comparison-v2`. `diagnostic_coverage` labels old rows without D1;
absence of new fields is not evidence that no curl failure occurred.

The exact 278-row reference lives in `docs/xray-both-success-core-failure.csv`,
with provenance and a required SHA256 in `docs/XRAY-COMPARISON-COHORT.json`.
It contains only protocol source filenames, URI hashes and historical reasons.
All members succeeded in Xray runs 37773848427 and 37705387725 and failed in core
run 37855491775. This describes recorded runs, not permanent node availability.

Outputs include `xray-cohort-summary.json` and `xray-cohort-comparison.csv`.
They separate current PASS/FAIL/PARSE_INVALID outcomes, members absent from the
selected Pre, and selected members with missing results. Missing members never
count as failures or recoveries. The cohort does not filter or alter test inputs;
PASS recovery by itself does not prove which repair caused it.

## Verification

`test_node_diagnostics` exercises the real runner with deterministic owned
processes: first versus later failures, cancellation, curl 35, curl 28, process
wait timeout, startup exit, independent HTTP statuses, all 2xx statuses and secret
exclusion. Its portable sanitizer suite and POSIX process suite are registered
in `tests/run_validation.py`.

`test_node_runner` exercises real curl and the actual core through independent
local VLESS/HTTPS peers, including a deliberately invalid inner TLS endpoint.
Linux validation does not establish Windows execution; the same validation
workflow must check Windows. No public-node retry, endpoint fallback, TLS
verification bypass or core repair is included in D1.

curl metrics and error reference: https://curl.se/docs/manpage.html and
https://curl.se/libcurl/c/libcurl-errors.html.
