# Custom Xray branch instructions

- Implement core changes and new executable test/build tools in Go. Do not add
  Python, PowerShell or another implementation-language toolchain to this fork.
  Preserve upstream protobuf, configuration, documentation, assembly and original
  packaging files in their native formats. Do not disguise language statistics
  using Linguist overrides.
- Compare features against VPN-Core-Test main at the exact commit in
  `fork/manifest.json`. Do not recreate the deleted native-core branch.
- Preserve upstream history, module imports, license and attribution. Port small
  missing capabilities; do not import the old engine as a fallback process.
- Preserve main, releases and private application/node/profile/key material.
  Keep generated binaries, local evidence and private reports outside Git.
- Reproduce missing behavior, run affected tests and build the same source before
  publishing. Record failures and prerequisites; do not weaken assertions, remove
  checks or retry protocol failures until they pass.
- Distinguish compilation, runtime/race/wire, platform/package and Internet/SDK
  acceptance. A cross-build is not runtime acceptance on the target OS.
- Do not drop supported protocols to make the binary smaller. Measure size and
  performance claims against equivalent builds.
- Add support without reinterpreting configurations that work on pinned upstream
  `701af60772cda123492f86e383e1fdba066614a9`. Preserve ignored fields and AUTO
  fallbacks as well as ordinary defaults. Ambiguous VMess/SOCKS legacy behavior
  requires the separate per-node `legacySettings` opt-in (and protobuf gate),
  never an automatic retry, downgrade or a shared-default change.
- New cipher/protocol selectors may enter added paths. A behavior fix affecting
  an original path must be separately opted into or explicitly authorized;
  preserve the owner's existing race/stability fixes. Run the shared original
  behavior fixture on pinned upstream and the fork, and test original and added
  runtime paths together before publishing. See `fork/VERIFICATION-PRESERVATION.md`.
- Inherited workflows are intentionally inactive in `.github/upstream-workflows`.
  The owner-authorized manual-only compatibility workflow is
  `.github/workflows/core-validation.yml`, reusing the existing registered path
  without changing main. It runs tests/reports only, with no packaging, mobile,
  release, push or scheduled jobs. The owner will dispatch it personally.
  Do not enable CI, dispatch runs, publish releases, monitor runs or open a PR
  without a user request covering that action.
