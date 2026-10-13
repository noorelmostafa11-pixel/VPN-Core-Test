# SSH outbound

`ssh://username:password@host:22?hostkey=SHA256%3A...` creates an SSH
`direct-tcpip` connection. Destination DNS is handled by the SSH server.
The host key is mandatory: specify either its `SHA256:` fingerprint or an
explicit `known-hosts` file. If both are present, both must verify. The core
never uses `InsecureIgnoreHostKey` and does not add host keys automatically.

Password and public-key authentication are supported. `private-key` selects
a PEM/OpenSSH private key file (at most 64 KiB); `private-key-passphrase`
decrypts it if needed. A known-hosts file is capped at 8 MiB. Percent-encode
query values in node URIs. Existing ini/JSON routing, local proxies, TUN,
SDK protection, TCP detours and destination policies use the same outbound.
Unknown options are rejected. SSH is TCP-only and returns `SSH_TCP_ONLY` for
UDP; no shell, remote command, SSH agent or SSH server is provided.

Each flow owns its own SSH transport so cancellation of a blocked channel-open
cannot strand a goroutine or disrupt another active flow. Connect/handshake/
channel-open honor the connection timeout; close joins the transport and
request/channel workers. The shared engine flow limit still applies. No SSH
workers are started when the outbound is unused.

Implementation uses the already pinned BSD-3-Clause
`golang.org/x/crypto/ssh` 0.58.0. Its upstream notices accompany the binary.
Tests verify password/private key/known-hosts authentication, payload transfer,
16 connect/disconnect cycles, active owner shutdown, blocked channel timeout,
protection failure, wrong host key/password and UDP rejection. An independent
Paramiko 5.0.0 peer separately verifies direct-tcpip payloads, repeated close
and authentication/host identity rejection. Paramiko is a test dependency and
is not part of the Go runtime. These are local tests, not public SSH node
Internet or Windows TUN route/DNS acceptance.
