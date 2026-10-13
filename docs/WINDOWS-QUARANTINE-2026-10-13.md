# Windows execution incident — 13 October 2026

On 12 October at 15:36:16 Dubai time, Windows Defender detected the locally
built Go 0.5.2 executable as `Trojan:Win32/Bearfoos.A!ml`. Its log records
quarantine at 15:36:38. The final protocol event in the host's core log was at
15:36:14, immediately before detection. A subsequent host recording shows a
rapid "12 attempts used" error. The displayed 1,756 is the country's catalog
size, not evidence of 1,756 successful protocol tests.

On 13 October, both a renewed comparison and diagnostic launch failed with
Windows error 225. Defender then quarantined the build-directory and local
integration copies. The affected executable's recorded build SHA256 is
`6ff5de034aa63dc254fecf93d41fb5a8f27b1378ef1a22dcd47eabfa8e3b3329`,
from source `1bfd433f94c31d38ed66a48cd7cd6f0c1a6edc73`, Go 1.27.1.
Signature version recorded during diagnosis: `1.459.691.0`.

These records establish blocked execution and quarantine. They do not establish
whether the detection is a false positive or that every earlier failed node was
caused by this incident. There was no Go panic in the captured host log.
Fresh Windows execution and long-cycle acceptance remain unverified while the
file is quarantined. Existing CI and earlier Internet passes must not be used
as evidence that this detection has been resolved.

Host software must distinguish missing/blocked executable, port conflicts,
storage failure and network-restoration failure from a failed VPN node.
Such host failures should stop scanning and preserve the cursor/favorites;
cleanup must not query `HasExited` on a process whose `Start` failed and mask
the original Windows error. This host correction was validated locally with
64 missing-core attempts, 16 failed starts, an occupied-port check and the
host's connection service. Application code remains outside this repository.

[Microsoft's error-code documentation](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)
identifies 225 as blocked infected/potentially unwanted software and 226 as
removal of such a file. Reviewing the detection is a separate unresolved
requirement. No exclusions or protection changes were made during diagnosis.
