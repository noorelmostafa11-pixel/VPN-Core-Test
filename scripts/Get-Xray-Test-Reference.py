"""Install a hash-pinned official Xray only for CI wire tests, never packaging."""
import argparse
import hashlib
import io
import os
import pathlib
import platform
import subprocess
import tempfile
import urllib.request
import zipfile

VERSION = '26.7.28'
# GitHub's official v26.7.28 asset SHA256 digests, verified 14 October 2026.
ASSETS = {
    ('Linux', 'x86_64'): ('Xray-linux-64.zip', '8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40'),
    ('Windows', 'amd64'): ('Xray-windows-64.zip', 'c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1'),
    ('Darwin', 'x86_64'): ('Xray-macos-64.zip', '812f7d9de6d3506795eabda2f6928ba301c632c3fe6fa39c52ea8e0ed9e4e244'),
    ('Darwin', 'arm64'): ('Xray-macos-arm64-v8a.zip', '9b99a351febe31b7e0c7f22deeb1577a1da0b98aaa51aec7fd17832e68cf63d6'),
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--github-env', action='store_true')
    args = parser.parse_args()
    key = (platform.system(), platform.machine().lower())
    if key not in ASSETS:
        parser.error('no pinned Xray test asset for this runner')
    name, digest = ASSETS[key]
    url = f'https://github.com/XTLS/Xray-core/releases/download/v{VERSION}/{name}'
    request = urllib.request.Request(url, headers={'User-Agent': 'vpn-core-independent-wire-tests'})
    with urllib.request.urlopen(request, timeout=90) as response:
        data = response.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit('official Xray test archive hash/size mismatch')
    output = pathlib.Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir())) / f'vpn-core-test-xray-{VERSION}-{key[1]}'
    output.mkdir(parents=True, exist_ok=True)
    executable = output / ('xray.exe' if platform.system() == 'Windows' else 'xray')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        item = archive.getinfo(executable.name)
        if item.file_size > 256 * 1024 * 1024:
            raise SystemExit('Xray test executable exceeds bound')
        executable.write_bytes(archive.read(item))
    executable.chmod(0o755)
    version = subprocess.check_output([str(executable), 'version'], text=True, timeout=10)
    if f'Xray {VERSION} ' not in version:
        raise SystemExit('Xray test executable version mismatch')
    if args.github_env:
        with pathlib.Path(os.environ['GITHUB_ENV']).open('a', encoding='utf-8') as stream:
            stream.write(f'VPN_CORE_REFERENCE_XRAY={executable.resolve()}\n')
    print(f'Pinned test-only Xray {VERSION}: {executable}')

if __name__ == '__main__':
    main()
