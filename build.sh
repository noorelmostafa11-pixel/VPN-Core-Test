#!/usr/bin/env bash
# Build the selected runtime target from repository source.
set -euo pipefail
exec python3 "$(dirname "$0")/scripts/Build.py" "$@"
