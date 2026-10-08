# Embedding SDK: lifecycle and diagnostics in 0.4.11

Existing ABI 1/2 exports and URI/protocol behavior remain available. This release
adds `vpn_core_read_event` and `vpn_core_pending_callbacks` without removing
existing calls. Use the header shipped with the matching native build.

Plain TCP half-close is delivered before waiting for the server's reply/EOF.
This fixes an empty-finish path that retained a VLESS worker and both sockets
until the server timeout; protocol framing and trailing responses remain intact.

## Stop, deadlines and host resource lifetime

`Stop` requests shutdown and returns without joining callback threads. Listener
acceptance stops and cancellable socket/TLS/provider waits progress on the run
worker. Polling uses short intervals; scheduling and host callback execution
prevent a universal wall-clock guarantee. A connect deadline bounds the core's
wait for bootstrap DNS, not arbitrary application code.

Resolver and protection callbacks execute outside shared registry locks, with
leases pinning their function pointers, user context and output buffers. At most
16 C++ DNS jobs may be outstanding, including timed-out jobs and system lookups.
Further DNS jobs report `DNS_CALLBACK_BUSY`. A resolver that ignores cancellation
can remain active after timeout or Stop; a synchronous protection callback can
also remain active. Neither is killed by force. Other requests can progress while
the callback remains alive. A host callback must be safe for concurrent calls.

`run_config` stays in STOPPING and does not return until all callback leases have
drained and every C++ DNS worker has been joined, including native thread-local
cleanup. Successful DNS calls also join their own worker before returning. A
timed-out or cancelled call leaves its worker owned until it finishes or run
shutdown drains it; shared registry locks are not held while joining. Keep
callback objects, user resources, core/provider modules and JNI/.NET
references alive until that return. An indefinitely blocked host callback means
an indefinitely draining run. The application must arrange its eventual return;
starting another run before then returns 2. Callbacks must not synchronously wait
for the run to finish or reconfigure/reenter run. SDK references remain pinned
through the blocking call. `vpn_core_pending_callbacks` exposes outstanding
leases; zero alone does not replace joining the run worker.

## Connection errors and UDP silence

`vpn_core_read_event(buffer, capacity)` returns UTF-8 JSON byte count excluding
NUL, zero when empty, or negative required capacity including NUL without
consuming the event. One consumer drains the queue. Events include connection ID,
timestamp, phase, reason code, native/HTTP status where known and negotiated TLS
metadata. Raw URI, credential, destination, error message and payload are omitted.
The queue holds 256 events; oldest events may be dropped, recorded in
`dropped_before`. Events reset at the next accepted run. Java `readEvent()` and
.NET `ReadEvent()` expose the same diagnostics.

DNS errors distinguish `BOOTSTRAP_DNS_FAILED`, `BOOTSTRAP_DNS_TIMEOUT`,
`DNS_CALLBACK_BUSY` and cancellation. Socket rejection reports
`SOCKET_PROTECTION_FAILED`. Optional INI `udp_response_timeout_ms` (0 by default,
maximum 600000) reports `UDP_NO_RESPONSE` for a sent destination without a reply.
It never declares the node UNSUPPORTED and never substitutes direct traffic. UDP
has no acknowledgement: silence can reflect application behavior or network
loss. Existing send/receive errors retain their diagnostic codes.

# Embedding SDK — Windows and Android

The engine retains the ABI 1 version/run/stop functions and adds ABI 2
`vpn_core_run_config`, `vpn_core_abi_version`, state and bound-port queries.
Source URI parsing, inspection metadata, TLS verification and TCP protocol
support are retained. The engine now offers SOCKS5 TCP CONNECT and UDP ASSOCIATE.
The package is an engine SDK, not an APK or a full-device Windows VPN application.

## Lifetime

Run blocks: use one application-owned worker, wait for state RUNNING and a
nonzero listen port, and request stop before joining that worker. Return 2 means
another run is active; return 1 means startup failed. STOPPED and port zero
indicate the worker has exited its engine run. Do not unload the engine or Go
provider during process lifetime. ABI 1 callers continue to work.

Network callbacks may arrive on several native/provider threads. Protect returns
1 only on success; an exception/rejection aborts the outbound connection. Resolve
returns newline-separated numeric IP addresses and must not recursively call
the engine. Callback data stays alive until run returns. The Windows handle is
64-bit SOCKET; Android/POSIX uses an fd. Never close the provided socket.

## Windows

Build with `build.ps1 -Target windows`. Distribute `vpn-core.dll` and `vpn-tls.dll`
beside the application, plus the licenses from the target ZIP. C/C++ uses
`core-api.h`; .NET 6+ can use `sdk/windows/VpnCore.cs`. The command-line EXE remains
available. Compilers, Python and Go are build dependencies, not user dependencies.

The application owns its tunnel adapter, routing and TUN-to-SOCKS layer for
full-device VPN. Configure that layer to use the returned SOCKS port and UDP
ASSOCIATE. Local SOCKS alone does not route every Windows application.

## Android

Each Android build now also creates `libvpn-jni.so` and a versioned ABI-specific
AAR, with Java 8 bytecode, JNI libraries and consumer shrinker rules. A JDK 17+
with `javac` is required at build time; no Android SDK/Gradle is needed to package
this Java-only library. The minimum SDK matches the selected native API (23 by
default). Four ABI builds can be combined into one AAR:

```sh
python scripts/Package-Android.py --build build/android-arm64-v8a \
  --build build/android-armeabi-v7a --build build/android-x86_64 \
  --build build/android-x86 --output dist/vpn-core-android.aar
```

Copy the matching AAR into the application's `app/libs`, add
`implementation(files("libs/vpn-core-android.aar"))`, and import
`com.noorelmostafa.vpncore.NativeCore`. Package only one combined AAR or one ABI
AAR to avoid duplicate Java classes. Native libraries must be available to the
Android linker together. Extracted JNI packaging (`jniLibs.useLegacyPackaging =
true`) supports Android 23+; for uncompressed APK libraries the application must
also perform 16 KiB ZIP alignment. ELF 16 KiB alignment is checked by this repo.

Pass `NativeCore.NetworkHooks`: protect invokes the existing
`VpnService.protect(fd)`; resolve obtains numeric addresses from the selected
underlying `Network.getAllByName(host)`. This covers C++ TCP/SS UDP and provider
HTTP/2, HTTP/3, QUIC, mKCP and ECH resolver connections. Do not resolve node/resolver
hostnames through the VPN tunnel being established. Hook failures fail closed.

The application still owns VpnService consent, foreground-service lifecycle,
TUN, routes and DNS configuration. Reuse its existing TUN-to-SOCKS layer and send
both TCP and UDP through this engine. A working engine build does not verify that
application layer or an actual Android device. No emulator is started by the
build workflow. `runStandalone` is only for proxy use without a VPN service.

## UDP and DNS

SOCKS5 UDP associations are loopback-only and bound to their TCP control peer.
The UDP relay port is returned by UDP ASSOCIATE, not the TCP listener port.
Association lifetime ends with the control connection or engine stop; idle
destination tunnels expire according to the existing idle timeout. Failed stream
destinations (including VMess nonce exhaustion) are retired; a later datagram
opens a fresh destination session. The relay
accepts IPv4, IPv6 and ASCII/IDNA target names; the remote proxy resolves target
names. DNS datagrams use the same encrypted proxy path; there is no direct DNS
fallback for user traffic. Bootstrap resolution is a separate host callback.

VLESS uses UDP command 2 and length-prefixed packets without TCP Vision padding;
the original flow/config remains unchanged. Trojan uses UDP command 3 and
address/length/CRLF frames. VMess uses UDP command 2 and preserves authenticated
chunk boundaries; `zero` uses the protocol's framed `none` packet mode for UDP.
Shadowsocks uses native UDP, including the existing stream/AEAD and SS2022
ciphers, session validation, identity headers and replay protection. SIP003
plugins wrap TCP only; the upstream Shadowsocks server must also expose UDP.
Server availability/UDP policy remains a network result, not a URI rejection.

RFC 1928 fragments are dropped. Oversized datagrams are dropped rather than
split into different application packets. VMess empty chunks mean EOF, so empty
UDP payloads are not forwarded using VMess. Associations bound memory and live
destinations (up to 64 per association and the configured connection limit).

Wire references: [Trojan](https://trojan-gfw.github.io/trojan/protocol),
[Shadowsocks SIP022](https://shadowsocks.org/doc/sip022.html),
[SIP023](https://shadowsocks.org/doc/sip023.html),
[VLESS encoding](https://github.com/XTLS/Xray-core/tree/main/proxy/vless/encoding),
[VMess encoding](https://github.com/XTLS/Xray-core/tree/main/proxy/vmess/encoding).
