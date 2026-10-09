# Ordered verification targets with one network budget

Prepared against `VPN-Core-Test@edb549964dcd1a558eff84cd07f8f747c63108dd`.

`scripts/Test-Nodes.py` uses these default targets, sequentially:

1. `https://example.com/`
2. `http://connectivitycheck.gstatic.com/generate_204`
3. `https://www.microsoft.com/robots.txt`

The default `--timeout 10` is one total network budget after the core is ready.
Each request gets at most one third of that budget, approximately 3.33 seconds.
The monotonic global deadline also limits the last request. A fast failure starts
the next request immediately. A successful request stops the sequence immediately;
no later target is contacted and no unused part of the slot is awaited. Startup
and owned core shutdown retain their separate existing deadlines.

Curl's connect and full-request deadlines fit within each slot, with a small
flush allowance inside that same slot so its original exit code and metrics can
be collected. The subprocess watchdog shares the global deadline; there is no
additional three-second wait per request. Watchdog expiry retains a null curl
exit code instead of fabricating exit 28. A late or missing result is never PASS.
The core connection deadline follows the request slot, respecting the existing
one-second minimum configuration value. The original node URI is unchanged.

Success still requires curl exit 0 and a complete response with HTTP 200–299.
Empty 204 responses remain valid. HTTPS certificate verification remains enabled;
curlrc is disabled, insecure flags are absent, and redirects may use HTTPS only.
The single built-in Google target permits its explicit initial HTTP request.
That success proves an HTTP response through the node, not inner HTTPS/TLS
verification. `request_scheme` distinguishes it in the report.

An explicit `--url` remains a single HTTPS-target override using the total budget,
for existing callers and independent test fixtures. Credentials and custom HTTP
overrides remain rejected. Report fields export bounded endpoint labels rather
than custom URLs, stderr or original node credentials.

## Reports

`probe_attempts` retains each attempted endpoint, curl exit code and TLS error
class, HTTP status, request scheme and result. `success_endpoint` identifies the
winner; `network_duration_ms` records the whole sequence. Unattempted targets are
not counted as failures. A successful fallback supplies the top-level curl fields.
If all attempts fail, the first attempt remains the top-level request failure;
later attempts are retained separately. Core startup, readiness, first failure
and cleanup diagnostics continue to be recorded independently by D1.

Shard summaries include `probe_endpoints`, `network_budget_seconds`,
`success_endpoints` and `probe_curl_reasons`. Original source/ID hashing and coverage
checks remain unchanged. Comparison with earlier runs must account for the target
policy change; a recovered PASS alone does not prove a core protocol repair.

## Verification limits

`test_node_budget` tests the 10-second shared deadline using a controlled clock,
every winning position, early failure, watchdog expiry, invalid HTTP statuses,
certificate failure, safe reporting and the HTTPS override. Independent local
SOCKS/HTTP/TLS peers exercise actual curl, including authenticated HTTPS success,
HTTP 204, the last target winning, prohibited HTTPS downgrade and three real
timeouts sharing one deadline. D1's existing process and sanitizer tests run
alongside them. Tests use no public nodes and build no core executable.

The new tests are registered in Linux validation and the existing manual Windows
validation. Local execution was on Linux; native Windows execution is not yet
verified. No workflow has been dispatched for this preparation.
