# SSH client and forwarding server

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
UDP; no shell, remote command or SSH agent is provided.

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

## Forwarding server

The opt-in server implements authenticated `direct-tcpip` forwarding, following
[RFC 4254 section 7.2](https://www.rfc-editor.org/rfc/rfc4254#section-7.2).
It uses the same protected outbounds, routing and shared flow budget as other
inbounds. It does not start a shell, execute commands, transfer files or expose
a remote port listener. Reverse forwarding remains a separate pending feature.

```json
{
  "protocol": "ssh",
  "listen": "0.0.0.0:22",
  "key_file": "host-key",
  "password": "client-password",
  "options": {"username": "vpn-user"}
}
```

`key_file` is an explicit PEM/OpenSSH host private key, bounded to 64 KiB;
`options.host-key-passphrase` is optional. The configured user can authenticate
with the password and/or `options.authorized-keys`, an OpenSSH public key file
bounded to 1 MiB and 128 keys. At least one authentication method is required.
Unsupported authorized_keys options are rejected; restrictions are never
silently discarded. Empty/unknown user credentials are not accepted. Clients
must verify this host key, as required by the outbound implementation above.
Only one configured username is supported per listener in this extension.

There are at most 64 physical SSH connections per listener and three
authentication attempts per connection. Each forwarded channel consumes the
engine's shared flow budget. Physical handshakes have a deadline; idle physical
connections and channels close through joined watchers. A per-channel deadline
is not applied to the shared physical socket. Closing a channel leaves other
channels alive. Claimed SSH origin addresses are not trusted routing metadata;
the actual accepted connection's source is used.

Local tests cover 32 connect/disconnect cycles, eight concurrent large channels,
password/public-key rejection, forbidden channel/reverse requests, physical
idle close, owner loss, protection failure and flow-budget exhaustion/recovery.
Independent Paramiko 5.0.0 clients verify payloads in 16 cycles for each of
password and public-key authentication, host identity, authentication rejection,
and rejection of session/command channels. Server credentials and private keys
are synthetic test fixtures and are not distribution artifacts.
