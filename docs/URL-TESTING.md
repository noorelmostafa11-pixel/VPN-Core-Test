# Optional HTTPS health selection

Routing groups can opt into `url_test` to select an outbound only after an
actual HTTPS response and body have been verified. A TCP/QUIC handshake is not
treated as proof of Internet connectivity. Node TLS/SSH trust rules, socket
protection, routing detours and the shared connection budget remain enforced.
The HTTPS destination itself also receives ordinary certificate/name validation.

```json
{
  "outbounds": [
    {"tag": "node-a", "uri": "socks5://127.0.0.1:1081"},
    {"tag": "node-b", "uri": "socks5://127.0.0.1:1082"}
  ],
  "groups": [{
    "tag": "automatic",
    "mode": "url_test",
    "members": ["node-a", "node-b"],
    "url_test": {
      "urls": ["https://probe.example/status"],
      "expected_body": "vpn-probe-ok",
      "interval_seconds": 30,
      "timeout_ms": 3000
    }
  }],
  "final": "automatic"
}
```

The example endpoint is a placeholder: configure real HTTPS endpoints whose
responses you intend to verify. Up to four URLs provide endpoint fallback,
sharing the node's total timeout so one unavailable site cannot consume the
entire budget. At least one response must have status 200, a nonempty body of
at most 64 KiB, and contain `expected_body` when configured. Redirects and
insecure TLS are not accepted. `ca_file` optionally supplies an explicit PEM
root bundle, capped at 1 MiB. No endpoint is probed unless explicitly configured.

The fastest currently verified member is selected; other verified members can
provide connection-establishment failover. No application payload is replayed.
Until a member passes, or if none remains healthy, dialing returns
`NO_HEALTHY_OUTBOUND`. Results expire after three configured intervals.
Group members must identify actual leaf outbounds, not nested groups or block
entries. Changing routing or selection creates a new proof generation; results
from the previous path are not reused to certify a changed path.

Limits protect large catalogs and active VPN traffic:

- At most sixteen node probes per engine round and four concurrent probes.
- A minimum five-second pause between rounds, including manual requests.
- A group interval of 5-3,600 seconds, default 30; a total per-node timeout of
  100-30,000 ms, default 3,000.
- Gradual scanning with a rotating cursor; refresh a working member first.
- Local protection errors or engine/client-budget exhaustion abort the round
  without declaring the remaining catalog unhealthy.
- One coalesced manual refresh request; bounded response headers and bodies.

A 1,700-node catalog does not launch 1,700 workers or exhaust the node list
after a local failure. Scanning is incremental, so a member near the end is not
necessarily tested in the first round. Current active connections retain their
path during updates. No health controller is created for profiles without this
feature. Disabling it through routing reload cancels and joins its workers.
Owner close interrupts blocked response bodies and joins probe/cancel workers.

Go SDK: `Engine.URLHealth()` returns redacted group/member state;
`Engine.RequestURLTest()` queues an extra round. The authenticated, loopback
management API exposes `GET /health` and `POST /health/check` (202 when queued).
It does not return node URIs, credentials, probe URLs or response bodies.

Local TLS fixtures test real bodies, site fallback, failed node selection,
empty/wrong bodies, HTTP errors, wrong certificates, 1,700-member bounds,
manual throttling, protection rejection, reload concurrency, API redaction,
feature disable and owner close during a blocked response. These are local
end-to-end HTTPS tests. Public-node acceptance requires running the configured
probe through those actual nodes. A TCP HTTPS result does not establish UDP
reachability or Windows OS route/DNS restoration.
