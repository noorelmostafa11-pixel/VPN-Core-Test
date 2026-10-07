# VPN-Core-Test

Public repository for manual Windows node testing of the **precompiled vpn-core 0.4.2**. No compilation or core-source changes are required.

## Required test bundle

Upload **`VPN-Core-Test-Public-Bundle.zip`** at the repository root using **Add file → Upload files**. It is a ZIP archive containing:

- `bin/vpn-core.exe` and `bin/vpn-tls.dll`, plus a checksum manifest
- `scripts/Test-Batch.ps1` and `scripts/Batch-Process.ps1`
- Four pinned Pre protocol lists (72,767 entries)
- Pre source manifest and feature census

Expected ZIP SHA-256:
`ba3c587921d8b9a8ad6487137eccb71a736f5137039a80d90ebe1535e9f05cfd`

The repository is public: all uploaded binary files and node URLs are public. Do not add private credentials.

## Running tests

1. Verify the ZIP is committed at repository root.
2. Open **Actions → Windows Pre Node Test → Run workflow**.
3. The workflow runs **15 Windows-2022 shards** at up to **8 concurrent node tests per shard**, each line assigned to exactly one shard. It checks the supplied EXE and DLL checksums and runs self-test before network tests.
4. Download artifacts named `vpn-shard-0` through `vpn-shard-14` from the workflow run. Each shard reports `results.csv`, `results.ndjson`, and `summary.json`.

All tests use `https://example.com/`, with a 10-second request timeout. Results are specific to the GitHub-hosted network, not necessarily the local machine. The workflow only runs when manually dispatched and **never builds or modifies the core**.

> Note: This workflow is not usable until the ZIP has been uploaded at repository root.
