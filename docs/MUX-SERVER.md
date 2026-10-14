# VMess / VLESS MUX server

Version 0.5.11-go accepts authenticated command-3 MUX on raw/optional-TLS VMess
and VLESS inbounds. VMess retains its encrypted chunk framing; VLESS sends its
normal response header before MUX data. No extra configuration is required.

The server supports New/Keep/End/Heartbeat frames, concurrent TCP sessions and
UDP sessions with destination metadata on each packet. This includes Xray's
default XUDP VMess path. Direct UDP uses an unconnected protected socket per
address family, keeping its source port stable across destinations and accepting
Full Cone replies; each destination/reply still evaluates the current routing.
Proxy decisions use the existing protected packet bridge. A failed destination
ends that session with the error option and leaves other sessions usable.

The parent has at most 128 sessions, each charged to the shared engine budget.
Metadata is at most 512 bytes and packet bodies at most 65,507 bytes. Each flow
has an eight-item queue. TCP applies bounded backpressure for the configured
connection timeout, then ends a stalled session; excess UDP datagrams may be
dropped. Writes on the parent are serialized and have the connection timeout.
One parent maintenance worker expires UDP sessions after 30 seconds and the
parent after the configured idle timeout; traffic in either direction keeps
the parent active. All workers are created on demand and joined on owner close.

XUDP global IDs are accepted as eight-byte metadata but are not used to migrate
sockets between parent connections. Forwarded source/local identity extensions
and automatic cross-parent migration remain pending. General outbound MUX,
sing-box smux, additional UOT paths and protocol server carriers also remain
pending; accepting XUDP frames alone is not full general multiplexing parity.

Go acceptance covers all VMess header padding lengths, real TCP byte streams
under backpressure, concurrent sessions, multi-destination/Full Cone UDP, shared
budget rejection with recovery on the same parent, malformed frame rejection,
protection failures, partial-frame cancellation, parent idle expiry and joined
owner shutdown. Independent Xray tests use encrypted TLS VMess and verified
TLS VLESS with four batches of eight concurrent 200,001-byte TCP payloads.
These are local wire/ownership results, not public-node or Windows route tests.

Wire references:
[MUX metadata](https://github.com/XTLS/Xray-core/blob/5ca6f4b/common/mux/frame.go),
[XUDP packets](https://github.com/XTLS/Xray-core/blob/5ca6f4b/common/xudp/xudp.go),
[VLESS command framing](https://github.com/XTLS/Xray-core/blob/5ca6f4b/proxy/vless/encoding/encoding.go).
