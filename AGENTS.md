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
- Inherited workflows are intentionally inactive in `.github/upstream-workflows`.
  Do not enable CI, dispatch runs, publish releases, monitor runs or open a PR
  without a user request covering that action.
