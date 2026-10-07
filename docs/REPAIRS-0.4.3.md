# 0.4.3: repository source and confirmed regression repairs

The source baseline is commit `4a19fc364ff42d5c19ced6b38d1d3b357768fa4d`
on `baseline/0.4.2`, recovered from the exact original 0.4.2 archive.
See `BASELINE-0.4.2.json` for archive and tested Windows binary hashes.
The installed runner had one known delta: its default network timeout was 10
instead of 20 seconds. 0.4.3 preserves the tested 10-second network timeout.

## Observed audit and scope

Input evidence: `VPN-Core-Test-Audit-37582872374(2).zip`, SHA256
`ba8f191e5d394975999ec96c8666d0a21a0bffc78417105b77a6337c7e6659d5`.
It summarizes run `37582872374`, not a fresh 0.4.3 network test.

| Evidence in the 0.4.2 run | Change and limits |
| --- | --- |
| 138 `OUTPUT_DRAIN_TIMEOUT` records; old helper waited at most 3 seconds for both pipe copies | Dedicated C# readers begin immediately on separate threads. Drain budget defaults to 10 seconds and is configurable. Timeout/copy faults still fail the row. Exact causes of all 138 historical events cannot be recovered from old logs. |
| 251 `HTTP_HEADER_DUPLICATE` records, all with sanitized field label `other` | Repeated opaque fields stay separately in `HttpHeaders.fields`; map lookup keeps the first value. They are not interpreted or comma-joined. Critical singleton/framing fields still reject duplication. Historical names and values were not recorded, so recovery of all 251 nodes is not claimed. |
| 13,985 `TLS_HANDSHAKE_VERIFY` records with diverse Windows native statuses | Certificate name/trust/validity/signature and token/message/ALPN/client-certificate statuses get specific reason codes. HRESULT and phase remain available. A provider diagnosis is not proof that the core or server alone is defective. |
| 11,069 `HTTPS_TLS_HANDSHAKE` records | Failure events include `tunnel_ready`, meaning successful SOCKS reply sent. Curl 35 is marked `HTTPS_REQUEST_OR_TUNNEL` unless an explicit pre-ready core failure proves the outer stage failed. SOCKS success does not prove remote authentication or body transfer. |
| 41 PASS records also contain core failure events | Retain both outcomes. One connection can fail while another succeeds. Diagnostics do not automatically revoke a successful HTTPS response. |

`PARSE_INVALID`, `ALPN_CARRIER_INCOMPATIBLE`, `TLS_PROFILE_CONFIGURATION`,
`HTTP_UPGRADE_STATUS` and `REALITY_AUTHENTICATION` remain reported categories.
No URI is guessed or repaired; no certificate, key or authentication verification
is bypassed. HTTP rejection retains the actual sanitized status. Explicit h2-only
HTTP/1 carriers still reject h2 negotiation. Established no-ALPN HTTP/1
compatibility stays covered by regressions.

## Validation and reproducibility

Authoritative evidence for a commit is its **Core Source Validation** run,
not historical files from older versions. Linux builds the test adapter, real
Go shared component and independent synthetic peers; Go race tests run too.
Windows builds production Schannel EXE and DLL from the same source, exercises
process handling on PowerShell 5.1 and 7, and tests verified TLS/WebSocket
connections with an ephemeral CA installed in the isolated runner's normal
CurrentUser trust store and removed afterward. Certificate-name rejection is
tested. No test-only config or insecure TLS mode is added to the released binary.

Helper regressions cover zero/nonzero exits, masked PowerShell properties,
timeouts, startup cleanup, exact bytes on two large pipes, 16 concurrent children,
and a grandchild holding stdout open beyond three seconds. Windows comparison
requires every inspection record and original node ID to match 0.4.2 for all
72,767 pinned inputs.

Network shards use the newly built, hash-checked Windows artifact. Each must
finish all selected records; cancellation or inventory errors fail the job.
PASS requires curl exit 0, HTTPS status 200 and a nonempty body. Body SHA256 is
recorded; this workflow does not pin example.com's body hash.
`ExpectedBodySha256` remains an optional stricter check. Public-server results
are time dependent and are distinct from local regression coverage.

Complete artifacts include source commit, runtime hashes and file manifest.
Release publication follows Linux/Windows build validation; long full-network
tests run separately and may still be in progress. Windows amd64 is built;
Android/TUN/JNI remains `NOT_VERIFIED`, without an Android-ready artifact.

Source access remains public by the owner's decision. `NOTICE.md` reserves
rights for original code; upstream licenses are preserved. Provenance hashes
identify a build and detect changes; they are not signatures, identity
verification or copy protection.
