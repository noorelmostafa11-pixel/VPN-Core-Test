# SSH TCP forwarding inside Xray

Date: 2026-10-17. Parent: `2abcb9ce538653f4d055d90c5ed859b820a96f6e`.

The pinned upstream has no SSH proxy handler. The prior fork CLI rejects an
explicit-port SSH node URI as an unsupported protocol. This batch adds a bounded
TCP-forwarding proxy, using the already pinned `golang.org/x/crypto/ssh` package
and the ordinary Xray handler, dialer, dispatcher, policy and core lifecycle.
No module version changes, alternate executable, SSH shell or engine fallback
are introduced. Existing protocol/security implementations and original schemas
are unchanged; only the new `ssh` configuration registrations are added.

The forwarding envelope follows [RFC4254 section7.2](https://www.rfc-editor.org/rfc/rfc4254#section-7.2).
The [Go SSH library](https://pkg.go.dev/golang.org/x/crypto/ssh) owns cryptographic
handshake, host-key verification, user authentication and SSH multiplexing.
No custom SSH cipher, signature, algorithm alias or legacy algorithm override
is added. Comparison scope is the exact main reference in `manifest.json`,
especially its `core/ssh.go` and `core/ssh_server.go`; this is partial capability
parity, not an assertion that every native option or endpoint has migrated.

## Selection and configuration

`ssh://user:password@host:22?hostkey=SHA256%3A...` selects the added handler
automatically. The port defaults to22. Percent-encoded credentials are preserved.
URI, version1 node JSON and typed Go `ResolveNode` input share the same decision,
reported as `NodeSSH`. Optional node transport metadata may specify `raw`/`tcp`
and `security=ssh`. Xray's outer stream is ordinary raw TCP with no extra TLS
layer; the SSH protocol itself authenticates and encrypts it.

Node import requires a nonempty username, password and canonical `SHA256:`
fingerprint of the server's SSH public-key blob, encoded in unpadded standard
base64. It is not a TLS certificate hash, SPKI hash or arbitrary public key.
Mixed credentials, insecure switches, TLS/REALITY/fingerprint settings, other
transports, unknown/conflicting parameters and local file references reject.
The node input never reads private-key or known-hosts files from URI metadata.

New full Xray JSON settings support these explicit operator configurations:

```json
{
  "protocol": "ssh",
  "settings": {
    "address": "127.0.0.1",
    "port": 22,
    "username": "user",
    "password": "synthetic-example",
    "hostKey": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  }
}
```

The example pin is synthetic and must be replaced with the verified server
fingerprint. Client `privateKeyFile` and optional `privateKeyPassphrase` select
explicit key authentication. A password may also be explicitly configured;
there is no agent, keyboard-interactive, environment credential discovery or
unauthenticated mode. `userLevel` selects the existing Xray policy.

```json
{
  "listen": "127.0.0.1",
  "port": 2222,
  "protocol": "ssh",
  "settings": {
    "hostKeyFile": "explicit-server-private-key-file",
    "username": "user",
    "password": "synthetic-example"
  }
}
```

The inbound also accepts `hostKeyPassphrase`, `authorizedKeysFile` and
`userLevel`. Password and authorized-key authentication are bound to the
configured username; no unauthenticated login is allowed. Key files are read
once when constructing the handler, not on every flow. Encrypted private keys
use the library's parser. The new SSH settings reject duplicate and unknown
fields; the decoders/defaults for every original protocol are unchanged.

## Runtime contract and bounds

- TCP `direct-tcpip` only. Domains are sent to the SSH server without local DNS;
  IPv4/IPv6 destinations retain their exact address representation. The server
  validates destination/origin fields before routing, and does not trust the
  origin string as the authenticated Xray source.
- One outgoing SSH transport per flow; no connection pool, protocol probing,
  reconnect or application-byte replay. Host verification precedes credentials.
- Handshake plus channel-open share the existing handshake deadline. Context
  cancellation closes the owned socket and joins the callback and SSH workers.
- Both directions support server-first data and half-close. Copy loops and
  request/stderr workers are joined on return. Per-channel inactivity/half-close
  limits use existing Xray policy and monotonic time, without setting a deadline
  on a shared SSH socket.
- A cooperative idle channel closes without canceling an active sibling. If a
  peer stops completing channel-close/control traffic beyond the handshake
  grace period, its whole SSH transport is closed so workers cannot remain
  stranded; this also terminates that peer's other channels.
- Each inbound has at most64 transports and64 active channels per transport.
  Channel requests are bounded to1024 bytes; usernames128 bytes, passwords and
  passphrases4096 bytes, private-key files64KiB, authorized-key files1MiB and
  at most128 distinct authorized keys. Authorized-key options reject rather
  than silently ignoring restrictions such as `from=` or forced commands.
- Channel targets go through the existing Xray dispatcher/routing. Channel-open
  confirmation accepts the routed channel, not proof of a successful remote
  application connection; payload/target checks establish the local test result.
- Shell/session, command execution, remote forwarding, agent forwarding and
  UDP are rejected. OpenSSH keepalive requests are answered without permitting
  other global operations. No weaker host-key/authentication fallback exists.

Known-hosts trust, private-key node input, host/user certificate policy, agents,
algorithm customization, general SSH sessions and application/SDK ABI parity
remain outside this batch. Explicit SHA256 host pins are currently mandatory.

## Verification

The peer tests use x/crypto directly, with independent configuration and literal
forwarding payloads. They do not use the added handler or conversion functions
to encode/accept the peer protocol. This is independent handler/wire exercise,
not a different SSH cryptographic implementation or an OpenSSH/main wire test.

- Outbound full JSON, URI, node JSON and Go input: server-first greeting and
  exact120003-byte fragmented streams, each for IPv4, domain and IPv6 targets.
- Inbound external SSH clients: password and authorized-key auth,8 concurrent
  channels on one transport, exact server-first/payload checks and real TCP
  targets through Xray. Encrypted client/server keys are exercised.
- Wrong host pin, password and username/key; stalled handshake/channel-open;
  malformed/unsupported channels, remote-forward rejection, keepalive and a
  routing rule proving the target is never dialed outside the dispatcher.
- Cancellation under confirmed SSH upload/download pressure, worker joining,
  delayed response after upload half-close, UDP rejection before any dial,
  idle/active sibling isolation and rejection of the65th concurrent channel.
- Protobuf validation, key-file size/regular-file checks, input parity and
  strict metadata bounds, followed by bounded fuzzing, race and original-path
  checks. Final result records are below.

The authorized-key file check initially reproduced rejection of a valid trailing
comment. The added parser now accepts blank/comment lines and duplicate keys,
while retaining rejection of key restrictions and the128-distinct-key bound.
The exact failing case then passed under race detection, including8 simultaneous
authenticated channels. No original fixture or failure assertion was relaxed.

Final source comprises1243 Go/protobuf/module paths, fingerprint
`7ab719395fdfa282d64864fa35acdcca0ddb5505b5ad8976425ad2e206a83d74`.
Toolchain: Go1.27.1 windows/amd64, GCC16.2 for race. The existing module files
are unchanged. New SSH protobuf source matches protoc33.5/protoc-gen-go1.36.11
regeneration with LF normalization; changed source formatting/diff checks pass.

The unchanged shared original-behavior fixture also passes pinned upstream
under race detection (8.562s), with SHA256
`f9497e45987e0e5f2cbf5d059e90ce31795efc6969e49ac2b07f9a69fdc86d65`.
Final affected-package race and original scenario results are recorded below.

URI, node-description and direct SSH protobuf fuzzing complete60026 executions
with2 workers per run and no failures (26.078s/20.592s/6.554s including setup).
Affected-package vet exits0 with no diagnostics. The new SSH cases also passed
race count3 before the comment-format correction (core94.466s); the correction's
targeted independent endpoint/key-format race checks pass (core17.923s,
proxy3.377s). This is not a whole-tree/TLS-suite pass; the known external ECH
test is unchanged and was not rerun.

Same-source normal-distribution CLI compilation passes with CGO0, trimpath and
stripping for Windows amd64, Linux amd64 and Darwin arm64. Windows version and
synthetic URI/node configuration checks pass. The private Windows artifact is
35952640 bytes, SHA256
`7df7b52c99b5418568b146aae9ff121acbadecc14e60b902b9671af65f14f17a`.
Its version reports `2abcb9c-dirty`, the parent plus this source, not a clean
future commit. Preliminary pre-correction artifacts are separate and are not
the final acceptance binaries. No size/performance improvement is claimed.

Final full affected-package race passes: SSH4.360s, config11.012s,
serial5.072s, main5.285s and core168.591s. The fork's full config suite includes
the unchanged shared original-behavior fixture. All20 selected unchanged
original scenarios pass under race detection (155.560s): modern VMess body,
TCP/UDP/mux/length modes, original SS AEAD and SOCKS TCP/UDP/mux/routing, and
VLESS/TLS/Vision/REALITY. These checks were rerun on the final source after the
authorized-key comment fix; earlier pre-correction results are retained
separately. Private logs use the `xray-ssh-final2-` prefix; build metadata and
the source/verification receipt stay outside Git under `report-review`.

All runtime evidence is local Windows amd64. Cross-compilation does not prove
Linux/macOS runtime, Internet/private-node compatibility, OpenSSH acceptance,
Android packages or SDK/application integration. No workflow dispatch or
monitoring, main/tag/release/PR mutation or distributable binary publication
belongs to this batch. Private synthetic keys, binaries and logs stay outside Git.
