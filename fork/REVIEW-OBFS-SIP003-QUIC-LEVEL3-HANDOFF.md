# Three outstanding extensions — staged additive integration / handoff

**Base owner branch:** `feature/xray-custom-core` @ `7565d4908de4828df36393228936b59c7c27d6eb` (verified before changes).  
**Separate review branch:** `feature/obfs-sip003-quic-additive-20261018`.  
**Full project build, independent peer interoperability and level-3 runtime: NOT_VERIFIED.**

## Implementation status

### 1. Shadowsocks authentic simple-obfs (HTTP and TLS)

**IMPLEMENTED AS AN EXPLICIT TRUSTED EXTERNAL-PLUGIN BRIDGE, NOT AN IN-PROCESS CODEC.**  
`infra/conf/node_trusted_sip003.go` accepts `plugin=obfs-local;obfs=http[;obfs-host=...]` or `obfs=tls`, plus the `simple-obfs` alias. It only runs a real **locally installed and SHA256-pinned** `obfs-local` executable supplied by an application through `ParseNodeURIWithTrustedSIP003`. Native Shadowsocks (including native SS2022) connects to the plugin through a loopback TCP port; the plugin itself implements authentic obfs wire behavior. No downloadable or remote-named executable is ever launched by regular URI or subscription imports.

**Not bundled or wire-tested:** the actual `obfs-local` executable and a compatible `obfs-server` counterpart. App packaging/permissions and real HTTP/TLS fixture tests remain required.

### 2. SIP003 / advanced v2ray-plugin

**IMPLEMENTED AS AN OPT-IN TRUSTED EXTERNAL-PLUGIN BRIDGE.**  
`infra/conf/sip003/runner.go` implements process lifecycle, SHA256 verification, restricted environment, required SIP003 `SS_*` variables, readiness and shutdown. The bridge accepts `v2ray-plugin` options for real external mux and mode handling (including declared QUIC) instead of aliasing mux=1 to plain WebSocket. Unsupported remote options, arbitrary local file overrides and remote-specified executables are rejected. Unknown external SIP003 plugin names require an application-approved binary and application-owned options. The existing in-process `v2ray-plugin;mux=0` parser is **unchanged**, preserving the owner's already-reviewed fix.

**App integration still required:** the app must explicitly approve a binary path and SHA256, keep the returned `io.Closer` for the lifetime of the outbound, and clean up on node changes. There is a small loopback bind/close/rebind interval (SIP003 expects the plugin to bind its own local TCP listener); it requires security/reliability assessment before production. External plugin mux/QUIC wire agreement is NOT_VERIFIED.

### 3. Legacy QUIC Chrome fingerprint

**PARTIAL, REAL NATIVE QUIC PROFILE; NOT COMPLETE UTLS EQUIVALENCE.**  
`transport/internet/quic/transport.go` opts into bundled `apernet/quic-go` `Config.ChromeParrot` and `ZeroLengthConnectionIDGenerator` on the client only when TLS `fp=chrome` is explicitly selected. The same native QUIC profile already existed in this fork's XHTTP/HTTP3 implementation. No unrequested change to the 12-byte CID, Reno/BBR/Brutal controls, packet camouflage, TLS certificate verification or server carrier; other unsupported fingerprints still reject.

**Still missing:** full browser/uTLS QUIC ClientHello byte-for-byte compatibility (the QUIC handshake layer still relies on `crypto/tls`), and wire traces against pinned real browser/QUIC implementations. Do not advertise this as complete Chrome uTLS.

## Source and staged tests

- `infra/conf/node_trusted_sip003_test.go`: simple-obfs HTTP/TLS option filtering, v2ray-plugin mux/mode, untrusted-node protocol boundaries and no implicit plugin execution.
- `infra/conf/sip003/runner_test.go`: pinned local test executable lifecycle, SIP003 environment forwarding, pin mismatches and local process termination. No upstream `obfs-local` binary was run.
- `transport/internet/quic/chrome_profile_test.go`: real configuration selection of ChromeParrot and preservation of legacy QUIC defaults.
- Old fixtures that incorrectly rejected `chrome` are updated to reject unsupported `firefox`; four-protocol URI tests added.

A stand-alone Go 1.23.2 Linux equivalent of the `sip003` supervisor and a self-executing helper process passed `go test -race -count=1 ./...` and `go vet ./...` on 2026-10-18. **This isolated copy is not the complete repository and no source-blob equivalence was verified.** New GitHub-source tests have been authored but not executed in the required Go 1.27.x complete module.

## Release blockers / owner gate

1. Run full Go 1.27.x build/vet/race on Linux, Windows, macOS and Android integration where needed.
2. Test both `obfs-local` HTTP/TLS against a real `obfs-server`; test external `v2ray-plugin` with mux=0, mux>0 and mode=QUIC using pinned independent plugin executables/peers. Preserve normal Shadowsocks and SS2022 handshake behavior.
3. Check plugin lifecycle, app cancel/restart and loopback ownership; no production use of the process bridge without an explicit trusted-binary distribution and approval plan.
4. Verify native Legacy QUIC ChromeParrot against independent packet traces, compare TLS ClientHello with real Chrome, and keep any full-uTLS claim blocked if it differs.
5. Confirm no regression for existing four-protocol URI imports, TLS validation and default QUIC listener behavior.

**Do not merge automatically into `feature/xray-custom-core`; the original branch and the previously staged XHTTP/XDrive/subscription branch remain outside this patch.**
