#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
GO_BINARY="${VPN_CORE_GO:-go}"
if [[ "$($GO_BINARY version)" != "go version go1.27.1 "* ]]; then
  echo 'Go 1.27.1 is required for this release.' >&2; exit 1
fi
export GOTOOLCHAIN=local
mkdir -p bin
python3 scripts/Apply-Component-Patches.py
(cd tls-provider; "$GO_BINARY" build -mod=vendor -buildvcs=false -buildmode=c-shared -trimpath -o ../bin/libvpn-tls.so .
 "$GO_BINARY" build -mod=vendor -buildvcs=false -o ../bin/xhttp-peer ../tests/xhttp_peer.go
 "$GO_BINARY" build -mod=vendor -buildvcs=false -o ../bin/vless-encryption-peer ../tests/vless_encryption_peer.go
 "$GO_BINARY" test -mod=vendor -race ./...)
"$GO_BINARY" build -buildvcs=false -o bin/ech-peer tests/ech_peer.go
"$GO_BINARY" build -buildvcs=false -o bin/mldsa-signer tests/mldsa_signer.go
flags=(-std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror -Wno-misleading-indentation -DVPN_CORE_TEST_BACKEND)
g++ "${flags[@]}" src/main.cpp -o bin/vpn-core-test -lssl -lcrypto -ldl -pthread
for probe in protocol crypto expansion schannel-state repair; do
  source="${probe//-/_}"
  g++ "${flags[@]}" "tests/${source}_probe.cpp" -o "bin/${probe}-probe" -lssl -lcrypto -ldl -pthread
done
./bin/vpn-core-test --self-test
./bin/vpn-core-test --check-components
./bin/schannel-state-probe
python3 tests/run_randomized_profiles.py --go "$GO_BINARY"
python3 tests/run_validation.py
