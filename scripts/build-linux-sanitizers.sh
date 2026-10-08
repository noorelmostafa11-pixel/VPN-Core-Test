#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Run build-linux-tests.sh first to build the components and independent peers.
flags=(-std=c++17 -O1 -g -Wall -Wextra -Wpedantic -Werror -Wno-misleading-indentation -DVPN_CORE_TEST_BACKEND -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie)
g++ "${flags[@]}" src/main.cpp -o bin/vpn-core-sanitized -lssl -lcrypto -ldl -pthread
for probe in protocol crypto expansion schannel-state repair uri-source; do
 source="${probe//-/_}"
 g++ "${flags[@]}" "tests/${source}_probe.cpp" -o "bin/${probe}-probe-sanitized" -lssl -lcrypto -ldl -pthread
done
# LeakSanitizer cannot access the build environment's process task inventory.
export ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1
export VPN_CORE_TEST_BINARY="$PWD/bin/vpn-core-sanitized"
export VPN_CORE_PROTOCOL_PROBE="$PWD/bin/protocol-probe-sanitized"
export VPN_CORE_CRYPTO_PROBE="$PWD/bin/crypto-probe-sanitized"
export VPN_CORE_REPAIR_PROBE="$PWD/bin/repair-probe-sanitized" VPN_CORE_EXPANSION_PROBE="$PWD/bin/expansion-probe-sanitized"
export VPN_CORE_URI_SOURCE_PROBE="$PWD/bin/uri-source-probe-sanitized"
./bin/schannel-state-probe-sanitized
python3 tests/run_validation.py --no-batch
