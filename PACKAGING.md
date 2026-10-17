# Offline per-target Xray packaging

This branch provides a Go packaging command. It packages **only the target you ask for**; `-target all` is opt-in. Neither packaging code nor the CLI build downloads runtime assets. This does not edit Xray protocols or upstream configuration behavior.

> **Current repository status (2026-10-17): NOT READY for a complete offline package.** The branch does **not yet** contain the `assets/shared/*.dat`, `assets/windows/*/wintun.dll`, `assets/windows/LICENSE-Wintun`, or vendored Go dependency sources (`vendor/modules.txt` and contents). The command deliberately fails rather than shipping a ZIP with missing files. Asset hashes must not be invented. Before promising clone-and-build without network, the owner must add and verify the actual redistributable upstream files and commit the complete `vendor/` tree. This is a one-time repository preparation requirement, not a per-build download.

## Usage (repository root)

Install the Go version required by `go.mod` (currently Go 1.27; Windows build previously used 1.27.1). From PowerShell, disable automatic Go downloads *before running* `go run`:

```powershell
$env:GOTOOLCHAIN = "local"
$env:GOPROXY = "off"
$env:GOSUMDB = "off"
go run ./tools/package -os windows -arch amd64 -offline
```

For ARM64 Windows choose `-arch arm64`. For Linux choose `-os linux -arch amd64` (or arm64 / arm), for macOS choose `-os darwin -arch amd64` (or arm64). Android ARM64 is a **CLI executable** target only, not an Android APK/AAR, JNI SDK, or proof of Android runtime integration.

```text
go run ./tools/package -list
go run ./tools/package -os windows -arch arm64 -offline
go run ./tools/package -target all -offline  # explicitly build all supported targets
```

Output for Windows/AMD64, when all prerequisites are present and build succeeds: `dist/Xray-windows-amd64.zip`. The archive contains `xray.exe`, `geoip.dat`, `geosite.dat`, `wintun.dll`, upstream `LICENSE`, Wintun's `LICENSE-Wintun`, and inherited `xray_no_window` launchers. Non-Windows archives contain target `xray`, geo files and `LICENSE`. All are built from the selected checkout's source. There is no hardcoded path to an installed application.

## Required tracked input files

```text
assets/manifest.json            SHA256 locks for each external runtime file
assets/shared/geoip.dat         common, only if routing rules need geo data
assets/shared/geosite.dat
assets/windows/386/wintun.dll   Windows 32-bit TUN driver library
assets/windows/amd64/wintun.dll
assets/windows/arm64/wintun.dll
assets/windows/LICENSE-Wintun   Wintun redistribution notice/license
vendor/modules.txt             and all vendored Go dependency sources
```

Only the selected target's Wintun DLL is included. `geoip.dat` and `geosite.dat` are shared and are included in every CLI archive. Wintun is a Windows TUN runtime dependency; ordinary proxy configurations do not require TUN. No Linux/macOS/Android Wintun file is created or used. See `proxy/tun/README.md` for OS-specific network behavior.

The repository currently pins the SHA256 of the two geo data files already used in `fork/check/main.go` at pinned Loyalsoldier/v2ray-rules-dat revision `a2d310e1de9ba35757f1633dda231192d114a306`. The bytes are **not present yet**. All added Wintun DLLs and `LICENSE-Wintun` must receive correct SHA256 values in `assets/manifest.json` before packaging. Only commit runtime binaries and geo files once source provenance, hashes and redistribution obligations are reviewed. In `.gitignore`, only narrowly scoped assets should be exempted from the binary/data ignore patterns. Never commit a generated `xray` binary or anything under `dist/`.

For true offline builds from a fresh clone, all Go modules must also be committed as source under `vendor/` with a `modules.txt` consistent with `go.mod`. `go mod vendor` is a **repository provisioning step**, not part of the offline packaging command; populating a missing module cache may otherwise contact outside services. The Go compiler/toolchain must be available locally.

## Fail-closed rules and verification

- The CLI refuses unsupported OS/architecture pairs or conflicting target flags.
- `vendor/modules.txt` must be present; compiled builds use `-mod=vendor`, `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `CGO_ENABLED=0`, and `GOWORK=off`.
- Every external asset is required to be a nonempty regular file, with a valid 64-character SHA256 pin and exact matching bytes. Missing files, hash mismatches, Go errors and missing vendored module files stop the command; no silently incomplete ZIP is created.
- Staging happens in a temporary directory and ZIPs are created via a temporary file before being published to `dist/`. An old completed ZIP may remain if a subsequent build fails; don't confuse its presence with a successful current run.
- The packaging command does not change the manual-only test workflow, dispatch Actions, push tags, publish releases, or run tests on remote hosts.

**Verification limits:** unit tests of the stdlib-only packaging utility can run without external dependencies (`GO111MODULE=off go test ./tools/package`). Actual full Xray compilation and runtime on every platform must be verified independently after all inputs have been committed. A cross-compile is not Windows/macOS/Android runtime acceptance.
