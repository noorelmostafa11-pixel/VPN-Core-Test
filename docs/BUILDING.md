# Building the original main core

Main retains the original C++ engine and Go TLS/QUIC provider. Go's rewrite
has its own branch. scripts/toolchains.json pins Go, desktop GCC, Android NDK
and the minimum Android API. Keep the vendored components and project patches.

```text
python scripts/Build.py --target windows
python scripts/Build.py --target linux
python scripts/Build.py --target android --abi arm64-v8a --ndk /path/to/ndk
python scripts/Package-Target.py --build build/windows-amd64
```

Desktop targets use amd64. Windows needs matching MinGW; Linux builds run on
Linux. Android supports arm64-v8a, armeabi-v7a, x86_64 and x86, with SDK/NDK/JDK.
A single ABI is the default. Build outputs remain untracked, with hashes and
source provenance. Ownership and dependency notices accompany distributions.

GitHub has one **Build & Test** workflow. Select main or feature/go-native-core
using GitHub's branch selector; targets follow the implementation automatically.
There are no additional Run inputs. Public node testing is an explicit CLI action.

Full original Linux regressions are also available locally:

```text
bash scripts/build-linux-tests.sh
bash scripts/build-linux-sanitizers.sh
```
