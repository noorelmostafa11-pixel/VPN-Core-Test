# Original project code and runtime notices

The files in `src`, `scripts`, `tests`, and the top-level project files in
`tls-provider` were written for this Vpn project.
They do not contain copied Xray, V2Ray or Trojan engine source and are not a
fork of an existing VPN engine. Published protocol formats and SHA-224
mathematical constants, and the standardized RFC 7541 Huffman table were used to implement interoperable messages.

All rights to the project's original files are reserved. No public open-source
license has been selected. See `NOTICE.md` for the project owner's distribution
notice; upstream component licenses continue to apply to their own files.

The Windows executable uses Windows system APIs and compiler runtimes.
MinGW-w64 startup/thread support and GCC C++ runtimes are linked by the build.
Their supplied copyright notices and GCC GPL/runtime-exception text are
preserved under `third_party`. These notices do not assert ownership of the
project's original protocol/connection code by those runtime projects.

Python, OpenSSL, curl, cryptography, hyper-h2/hpack, PowerShell, Wine and the external reference Trojan server were
development/testing tools. Their development executables and third-party protocol implementations are not shipped in this ZIP. Test scripts import test-only Python dependencies installed separately.
The Linux test adapter uses system OpenSSL when built locally; the Windows
executable does not link it.

Pinned TLS, QUIC, HTTP, and cryptographic component source and licenses are
preserved under `tls-provider/vendor`. These files remain the work of their
respective upstream authors. Project changes to nine component files are
recorded, with original and replacement SHA-256 hashes, under
`tls-provider/component-patches`. The project-authored portions of those
changes do not claim ownership of the upstream component code.

`bin/vpn-tls.dll` contains these library components plus project-authored
carrier, queue, and cryptographic glue. It contains no imported VPN engine.
See `docs/COMPONENTS.md`, `go.mod`, `go.sum`, and the preserved licenses for
the exact components and versions used by this release.
