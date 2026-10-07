# Current Pre connection coverage — 0.4.5

Verified on 2026-10-07 against `noorelmostafa11-pixel/VPN-Nodes-Pre`
commit `ab54b99dbca41be020facfcb35569ebfdf730f59` (07:12:36 UTC).
The implementation started from `VPN-Core-Test` commit
`24165d1fa9a9254c0739d35a21d83d8ceb3f5cd0`, version 0.4.4.
The four current source files, their byte lengths, row counts, Git blob IDs
and SHA256 hashes are recorded in `pre-current-source-manifest.json`.

## Complete source inspection

| Source file | Input rows | Supported configurations | Invalid configurations | Valid configurations with missing features |
| --- | ---: | ---: | ---: | ---: |
| shadowsocks.txt | 757 | 681 | 76 | 0 |
| trojan.txt | 12,347 | 12,302 | 45 | 0 |
| vless.txt | 53,765 | 52,944 | 821 | 0 |
| vmess.txt | 4,886 | 4,860 | 26 | 0 |
| Total | **71,755** | **70,787** | **968** | **0** |

`Audit-Pre-Support.py` invokes the actual built core for every input row.
It verifies the source bytes first, then checks complete line coverage and
each original URI's SHA256-derived node ID. Its report contains no complete
URIs, credentials, arbitrary error text or user-supplied option strings.
The coverage gate fails if a valid configuration is unsupported or the
manifest's expected supported/invalid counts change. Moving a supported row
into the invalid category cannot make the gate pass.

These are configuration-support results. They do not establish successful
connections to 70,787 public servers, and the 968 invalid configurations are
not a count of dead servers. Configuration families are inspected, not each
independently tested as a live server combination.

## Connection paths present among supported rows

| Carrier | Supported rows |
| --- | ---: |
| WebSocket | 46,081 |
| RAW / TCP | 19,281 |
| XHTTP / SplitHTTP | 2,911 |
| gRPC | 2,124 |
| Legacy HTTP/2 | 329 |
| HTTPUpgrade | 60 |
| mKCP | 1 |

The supported security configurations include TLS, REALITY, legacy XTLS and
explicit `security=none`. Existing paths include the three XHTTP modes,
HTTP/1.1, HTTP/2 and HTTP/3, Vision, legacy RPRX, ECH, WebSocket early data,
Shadowsocks AEAD/2022/CFB and v2ray-plugin, VMess AEAD/legacy authentication,
and VLESS ML-KEM/X25519 encryption. These implementations already existed;
this update adds the missing fingerprint and verifies the current inventory.

## Implementation changes

- The current VLESS file contains `fp=randomizednoalpn` at line 32,615.
  The parser now recognizes it and the actual TLS provider constructs the
  corresponding uTLS NoALPN handshake. An HTTP/1.1 WebSocket connection can
  proceed without a negotiated ALPN protocol; HTTP/2 carrier checks remain.
- Both randomized presets always offer TLS 1.3 and retain permitted TLS 1.2
  negotiation. Raw library defaults sometimes generated a TLS-1.2-only
  ClientHello, incompatible with a TLS-1.3-only endpoint. Preset weights now
  keep TLS 1.3 available and use the X25519 first-share selection. Randomness
  in the rest of the template remains. The existing TLS version, negotiated
  cipher and certificate/name checks remain in force.
- VLESS line 6,157 has XHTTP option fields inside `fm`, with no TCP/UDP mask
  lists. It now reports `FINALMASK_STRUCTURE_INVALID`. Its original URI is
  unchanged. A TCP mask of an unimplemented type inside a legitimate mask
  list still reports a missing `FINALMASK` feature.
- `Prepare-Pre-Snapshot.py` validates all four downloads before installing
  any of them and refuses to replace an existing different snapshot.
  Linux and Windows CI now audit this separately pinned current snapshot.
- `Get-Pre-Inventory.ps1 -Snapshot current` downloads this snapshot to
  `nodes/pre-current/protocols`. The default `baseline` and its original
  72,767 inputs remain available for the existing comparison workflow.

The old snapshot's **72,767** inspection records and node IDs were also
compared between the starting 0.4.4 executable and the 0.4.5 candidate:
**zero changes**. The existing CI comparison against the immutable 0.4.2
baseline remains in place.

## Validation and limits

- Full local regression run: **179 tests, 177 successful and two platform
  skips**; Go race checks also passed. **Seven production Linux tests**
  passed using the executable and shared library built from this candidate.
- Native Linux production executable and shared library build, standard
  cryptographic vectors and component ABI checks.
- Independent OpenSSL endpoints: 256 reproducible seeds per randomized
  preset on a TLS-1.2-only server and again on a TLS-1.3-only server:
  **1,024 authenticated TLS handshakes and matching data echoes**.
  NoALPN cases additionally verify the absence of the ALPN extension.
- Independent protocol peers cover all four protocols, XHTTP modes and HTTP
  versions, REALITY, ECH, Vision, VLESS encryption, XTLS and lossy mKCP.
  New NoALPN cases cover RAW/TLS 1.2 and 1.3, eight simultaneous WebSocket
  sessions, explicit ALPN option lists and rejection of a wrong certificate
  name, including when `allowInsecure=1` is present.
- The production Linux WebSocket test uses the normal provider and CA
  verification, not the OpenSSL test backend. It is also registered in the
  existing Windows production suite with its temporary trusted test CA.
- Integrity and report tests verify preservation of previous source files,
  redaction, row identities, and failure when a supported fixture regresses
  to invalid configuration.

Windows and Android execution must be confirmed by their CI results.
Public-node connectivity was not tested in this change. Inspection totals
apply only to the named Pre commit, not future refreshes of `main`.

## Reproduce

```sh
python scripts/Prepare-Pre-Snapshot.py
python scripts/Audit-Pre-Support.py --core build/linux-amd64/vpn-core --output pre-current-support
```

Windows, after building the selected source:

```powershell
.\scripts\Get-Pre-Inventory.ps1 -Snapshot current
python scripts/Audit-Pre-Support.py --core build/windows-amd64/vpn-core.exe --output pre-current-support
```

Both audit commands perform inspection only. Real batch testing can use
`Test-Batch.ps1 -Nodes nodes/pre-current/protocols` with the desired HTTPS
destination and timeout.

Reference behavior checked on 2026-10-07:
[Xray TLS presets](https://github.com/XTLS/Xray-core/blob/main/transport/internet/tls/tls.go)
and [legacy HTTP/2](https://github.com/XTLS/Xray-core/blob/v1.8.24/transport/internet/http/dialer.go).
The latter requires TLS or REALITY; 70 current HTTP/2 configurations without
either remain invalid. Reference sources were used to check formats and
configuration semantics; no VPN engine was imported.
