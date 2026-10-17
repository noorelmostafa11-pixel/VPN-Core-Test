# Per-target Xray release packaging

This branch includes a Go packaging command that follows the upstream Xray release approach: build the selected core from this checkout, download checksum-verified runtime assets at **packaging time**, and create a platform-specific ZIP. No external runtime binaries, vendored Go sources, installed VPN application or manually copied DLL/data files are needed in the repository. The host needs Go at the version required by `go.mod` and network access for first-time module downloads and the pinned runtime assets.

## Usage from the repository root

```powershell
go run ./tools/package -os windows -arch amd64
```

Creates `dist/Xray-windows-amd64.zip`, with `xray.exe`, `geoip.dat`, `geosite.dat`, `wintun.dll` for Windows AMD64, `LICENSE`, `LICENSE-Wintun`, and the original `xray_no_window.cmd`, `.ps1` and `.vbs` helpers. It does not use or modify any installed VPN application or previous Xray binary.

Other target choices:

```text
go run ./tools/package -list
go run ./tools/package -os windows -arch arm64
go run ./tools/package -os windows -arch 386
go run ./tools/package -os linux -arch amd64
go run ./tools/package -os darwin -arch arm64
go run ./tools/package -os android -arch arm64
go run ./tools/package -target all    # optional; only when every supported target is wanted
```

Each invocation packages **only the requested target**, except an explicit `-target all`. Android output is a CLI executable, not an APK, AAR or SDK. Cross-build success is not runtime acceptance on a target OS.

## Distribution inputs and integrity

The command downloads the two Geo files from pinned `Loyalsoldier/v2ray-rules-dat` revision `a2d310e1de9ba35757f1633dda231192d114a306`, using the SHA256 digests already recorded for compatibility testing in `fork/check/main.go`. For Windows it also downloads the official [Wintun](https://www.wintun.net/) `wintun-0.14.1.zip`, using the exact archive SHA256 pinned by the inherited Xray `scheduled-assets-update.yml` workflow. These three digests are recorded in [assets/manifest.json](assets/manifest.json). The entire Wintun ZIP is checked before any DLL or license file is extracted; `386` selects upstream `x86`. Windows packages include Wintun's supplied binary redistribution license. Respect that license's redistribution conditions.

The original Xray `LICENSE` and Windows helper scripts come directly from this repository. Go downloads the module dependencies declared by `go.mod`/`go.sum` as necessary; the build uses `-mod=readonly` to forbid changing module declarations during packaging. Nothing is committed to Git by the packaging command. Build artifacts and downloaded assets are discarded from temporary staging after ZIP creation; finished ZIPs remain in `dist/`.

The checks are fail-closed: rejected HTTP responses, missing archive entries, digest mismatches, missing licenses and Go build errors abort that target without publishing an incomplete ZIP. Already completed ZIPs from earlier invocations can remain in `dist/` if a later run fails; use the current command's exit status, not mere ZIP existence, to determine success. This is a **network-capable packaging command**, not an offline packaging mode. If a host cannot reach the pinned official asset sources, packaging fails rather than silently substituting unrelated files.

## Verification boundaries

Run packaging-unit tests without fetching the rest of the Go module graph:

```powershell
$env:GO111MODULE = "off"
go test ./tools/package
Remove-Item Env:\GO111MODULE
```

These tests cover target selection, verified HTTP acquisition, Wintun ZIP mapping, license inclusion, failure cases, environment variables, and ZIP safety. Actual full Xray compilation and runtime must still be tested on the requested target; the packaging unit tests alone do not prove that Windows networking or TUN works.

Only the Go packaging utility, checksum manifest, and documentation are changed; original protocols, configuration behavior and the manual-only test workflow are untouched.
