# SOCKS4 / SOCKS4a outbound addition

Date: 2026-10-16. Base: owner's `caa6720f9ee2149c178600f0e77aeac4def71714`
plus this patch. The owner's preceding self-validation, race and routing-stats
fixes are retained. No workflow/check/wire-runner logic is changed, dispatched,
restarted or monitored by this addition. Main and releases are untouched.

## Selection and behavior

Example outbound settings (synthetic local endpoint):

```json
{
  "protocol": "socks4a",
  "settings": { "address": "127.0.0.1", "port": 1080, "user": "optional-id" }
}
```

`protocol: "socks4"` selects local IPv4 resolution, while `"socks4a"` sends
domain names to the SOCKS server. Both use the SOCKS4 version4 CONNECT wire
format; the latter uses 0.0.0.1 and a NUL-terminated domain extension. The
existing `protocol: "socks"` also accepts settings `version: "4"`/`"4a"`/`"5"`.
An omitted version still means SOCKS5. Explicit alias/version conflicts and
unknown versions are errors, never automatic fallback. Both flat settings and
the existing single-member `servers`/`users` format are supported.

SOCKS4 domain lookup uses the host resolver with the existing handshake timeout
and caller cancellation; it selects an IPv4 result, rejecting IPv6-only answers.
This is not an implementation of main's full bootstrap/application DNS settings.
SOCKS4a domain mode does not invoke that local resolver. Literal IPv4 targets
remain IPv4 in either mode. IPv6 targets and the reserved 0.0.0.x domain-sentinel
range are rejected rather than creating an ambiguous request.

User IDs are optional, at most255 bytes, without NUL/CR/LF. They are not password
authentication and are not encrypted by SOCKS itself. Nonempty passwords are
rejected, including when the username is omitted; protobuf users are checked as
well as JSON configuration. TCP CONNECT only: UDP, Mux commands and BIND are
not advertised or converted into another version. Existing SOCKS5 TCP/UDP and
inbound implementations are preserved. Server reply must contain all8 bytes,
version0 and status90. Rejection codes, wrong versions and truncated replies
fail; no automatic retry of the protocol negotiation is added.

The [original SOCKS4 specification](https://www.openssh.org/txt/socks4.protocol)
and [SOCKS4a extension](https://www.openssh.org/txt/socks4a.protocol) define the
packet layouts. No cryptography, external module or native engine is added.
Protobuf ClientConfig field1 is unchanged, field2 selects version, and enum0
retains the SOCKS5 default for existing serialized configurations.

## Local checks

- Before implementation both `socks4` and `socks4a` outbound configurations failed
  as unknown protocols. The original failure log is retained outside Git.
- Tests check both JSON shapes, explicit/default versions, alias conflicts,
  unknown versions, user-ID boundaries, password rejection and unchanged SOCKS5
  configuration. Golden wire requests cover IPv4 and remote domain targets,
  fragmented writes/replies and preservation of immediate server-first bytes.
- Negative checks cover every response length0..7, statuses91/92/93/0/255,
  wrong response version, malformed accounts/domains, IPv6, invalid ports and
  unsupported commands. IPv6/UDP fail before invoking an outbound dialer.
  Injected resolver checks cover mixed families, IPv6-only, empty/error answers
  and cancellation before lookup.
- Four real loopback TCP sessions exercise the full in-process fork outbound:
  SOCKS4 IPv4/localhost, SOCKS4a IPv4/nonresolvable .invalid domain. An independent
  Go peer verifies exact headers and user ID, sends a greeting before any
  application data and echoes100002 bytes with fragmented application writes.
  Temporary peers are closed/joined; no public server or private node is used.
- All new tests passed ten race-enabled repetitions: proxy/socks5.161s,
  infra/conf5.015s. Full affected packages passed once with race detection:
  proxy/socks5.431s, infra/conf6.569s. Vet passed both packages. Host toolchain:
  Go1.27.1 Windows amd64, GCC16.2 for race. These are local addition checks, not
  a rerun or replacement of the owner's compatibility workflow.
- Existing upstream SOCKS scenarios also passed with race enabled34.063s:
  SOCKS5 TCP/UDP bridge, routed UDP, HTTP-over-SOCKS and inbound conformance.
- Protobuf regeneration is byte-reproducible with protoc33.5/plugin1.36.11,
  SHA256 `2317238d3f3066cb99392c69e48ac726ef58d58f12a647c2b32e1c31793bb432`.
  Changed-file formatting and diff checks pass; module dependencies, licenses,
  workflows and owner's README are unchanged.

This is not full feature parity, real Internet acceptance, mobile SDK/ABI or
foreign-OS runtime acceptance. Remaining protocol gaps are in COMPARISON.md.
