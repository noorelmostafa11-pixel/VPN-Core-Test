"""One source build entry point for laptops and GitHub Actions. No node tests."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / 'scripts/toolchains.json').read_text())
ANDROID = {'arm64-v8a': ('arm64', 'aarch64-linux-android'),
           'armeabi-v7a': ('arm', 'armv7a-linux-androideabi'),
           'x86_64': ('amd64', 'x86_64-linux-android'),
           'x86': ('386', 'i686-linux-android')}

def call(args, **kwargs):
    print('+ ' + shlex.join([str(a) for a in args]), flush=True)
    subprocess.run([str(a) for a in args], check=True, **kwargs)

def output(args):
    return subprocess.check_output([str(a) for a in args], text=True).strip()

def executable(value):
    found = shutil.which(value)
    if not found:
        raise RuntimeError('Required build tool is missing: ' + value)
    # Preserve clang++'s driver name: resolving its symlink to clang changes
    # C++ runtime linking on the Android NDK toolchain.
    return pathlib.Path(found).absolute().as_posix()

def build(a):
    host = {'Windows': 'windows', 'Linux': 'linux'}.get(platform.system())
    if not host: raise RuntimeError('Use a Windows or Linux build host.')
    target = host if a.target == 'auto' else a.target
    arch = a.arch
    if target != 'android' and arch != 'amd64':
        raise RuntimeError('Desktop builds currently target amd64. Android selects its architecture with --abi.')
    if target == 'linux' and host != 'linux':
        raise RuntimeError('Build Linux from a Linux environment; on Windows run this command inside WSL2.')
    go = executable(a.go)
    go_version = output([go, 'version'])
    if not go_version.startswith('go version go' + LOCK['go'] + ' '):
        raise RuntimeError('Install pinned Go ' + LOCK['go'] + '.')
    env = os.environ.copy()
    env.update(CGO_ENABLED='1', GOOS=target, GOARCH=arch, GOTOOLCHAIN='local', GOWORK='off')
    ndk_version = None
    if target == 'android':
        if not a.ndk: raise RuntimeError('Set ANDROID_NDK_HOME or pass --ndk with the pinned NDK directory.')
        ndk = pathlib.Path(a.ndk).resolve()
        properties = (ndk / 'source.properties').read_text()
        ndk_version = LOCK['android_ndk']
        if 'Pkg.Revision = ' + ndk_version not in properties:
            raise RuntimeError('Use pinned Android NDK ' + ndk_version + '.')
        arch, triple = ANDROID[a.abi]
        if a.android_api < LOCK['android_api']: raise RuntimeError('Android API must be at least 23.')
        tag = 'windows-x86_64' if host == 'windows' else 'linux-x86_64'
        tools = ndk / 'toolchains/llvm/prebuilt' / tag / 'bin'
        suffix = '.exe' if host == 'windows' else ''
        cc = executable(str(tools / ('clang' + suffix)))
        cxx = executable(str(tools / ('clang++' + suffix)))
        target_flags = ['--target=' + triple + str(a.android_api)]
        env.update(GOARCH=arch, GOARM='7')
        env['CC'] = shlex.join([cc, *target_flags])
        env['CGO_LDFLAGS'] = '-Wl,-z,max-page-size=16384'
    else:
        prefix = 'x86_64-w64-mingw32-' if target == 'windows' and host != 'windows' else ''
        cc = executable(a.cc or prefix + 'gcc')
        cxx = executable(a.cxx or prefix + 'g++')
        target_flags = []
        env['CC'] = shlex.quote(cc)
        machine = output([cxx, '-dumpmachine'])
        if 'x86_64' not in machine or ((target == 'windows') != ('mingw' in machine)):
            raise RuntimeError('Compiler target does not match ' + target + '-amd64: ' + machine)
        compiler_version = output([cxx, '-dumpfullversion'])
        if compiler_version != LOCK[target + '_gcc']:
            raise RuntimeError('Use pinned ' + target + ' GCC ' + LOCK[target + '_gcc'] + '; found ' + compiler_version)
    label = target + '-' + (a.abi if target == 'android' else arch)
    destination = pathlib.Path(a.output or ROOT / 'build' / label).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    call([sys.executable, ROOT / 'scripts/Apply-Component-Patches.py'])
    version = (ROOT / 'VERSION').read_text().strip()
    source_hash = hashlib.sha256()
    for directory in ['src','tls-provider','sdk','scripts']:
        for path in sorted((ROOT/directory).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix not in {'.pyc','.log'}:
                source_hash.update(path.relative_to(ROOT).as_posix().encode()+b'\0')
                source_hash.update(hashlib.sha256(path.read_bytes()).digest())
    if '#define VPN_CORE_VERSION "' + version + '"' not in (ROOT / 'src/version.hpp').read_text():
        raise RuntimeError('VERSION does not match src/version.hpp.')
    dirty = None
    try: commit = output(['git', '-C', ROOT, 'rev-parse', 'HEAD'])
    except (OSError, subprocess.CalledProcessError): commit = 'NOT_VERIFIED'
    if commit != 'NOT_VERIFIED':
        try: dirty = bool(output(['git', '-C', ROOT, 'status', '--porcelain=v1', '--untracked-files=normal']))
        except (OSError, subprocess.CalledProcessError): pass
    if a.require_clean and (commit == 'NOT_VERIFIED' or dirty is not False):
        raise RuntimeError('Release builds require a verified clean Git checkout.')
    with tempfile.TemporaryDirectory(prefix='.vpn-build-', dir=destination.parent) as td:
        stage = pathlib.Path(td)
        provider = 'vpn-tls.dll' if target == 'windows' else 'libvpn-tls.so'
        ldflags = '-s'
        if target == 'android': ldflags += ' -extldflags=-Wl,-z,max-page-size=16384'
        packet_tags = ['-tags=netstack'] if a.experimental_netstack else []
        call([go, 'build', *packet_tags, '-mod=vendor', '-buildvcs=false', '-buildmode=c-shared', '-trimpath',
              '-ldflags=' + ldflags, '-o', stage / provider, '.'], cwd=ROOT / 'tls-provider', env=env)
        flags = [*target_flags, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                 '-Wno-misleading-indentation']
        if target == 'windows':
            flags += ['-D_WIN32_WINNT=0x0A00', '-static', '-static-libgcc', '-static-libstdc++']
            libraries = ['-lws2_32', '-lsecur32', '-lcrypt32', '-lbcrypt', '-pthread']
            binary = 'vpn-core.exe'
            shared = 'vpn-core.dll'
        else:
            flags += ['-DVPN_CORE_PORTABLE', '-fPIC', '-fvisibility=hidden']
            libraries = ['-ldl', '-pthread']
            binary = 'vpn-core'
            shared = 'libvpn-core.so'
            if target == 'android':
                flags += ['-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384', '-static-libstdc++']
        if a.experimental_netstack: flags += ['-DVPN_CORE_NETSTACK']
        entry_flags = ['-municode'] if target == 'windows' else ['-pie']
        call([cxx, *flags, *entry_flags, ROOT / 'src/main.cpp', '-o', stage / binary, *libraries])
        call([cxx, *flags, '-DVPN_CORE_SHARED', '-shared', ROOT / 'src/main.cpp', '-o', stage / shared, *libraries])
        if a.experimental_netstack:
            probe = 'netstack-core-probe.exe' if target == 'windows' else 'netstack-core-probe'
            call([cxx, *flags, *(['-pie'] if target != 'windows' else []),
                  ROOT / 'tests/netstack_core_probe.cpp', '-o', stage / probe, *libraries])
        if a.experimental_netstack and target == 'windows':
            call([cxx, *flags, '-municode', ROOT / 'src/native-windows-launcher.cpp', '-o', stage / 'vpn-native-tun.exe', *libraries, '-liphlpapi', '-lfwpuclnt', '-lrpcrt4'])
        if target == 'android':
            notice = ndk / 'NOTICE'
            if not notice.is_file(): raise RuntimeError('Pinned NDK is missing its NOTICE file.')
            shutil.copy2(notice, stage / 'NDK-NOTICE.txt')
            call([cxx, *flags, '-shared', ROOT / 'sdk/android/jni.cpp', '-o', stage / 'libvpn-jni.so',
                  '-L' + str(stage), '-l:libvpn-core.so', *libraries])
            javac = a.javac or (str(pathlib.Path(os.environ['JAVA_HOME']) / 'bin/javac') if os.environ.get('JAVA_HOME') else 'javac')
            call([sys.executable, ROOT / 'scripts/Package-Android.py', '--build', stage,
                  '--abi', a.abi, '--version', version, '--min-sdk', str(a.android_api),
                  '--javac', executable(javac), '--source-commit', commit, '--source-fingerprint', source_hash.hexdigest(), '--source-dirty', str(dirty).lower(), '--output', stage / ('vpn-core-' + version + '-' + a.abi + '.aar')])
        if a.build_tests and target != 'windows':
            call([cxx, *target_flags, '-std=c++17', '-O2', '-pie', '-static-libstdc++',
                  ROOT / 'tests/core_api_smoke.cpp', '-o', stage / 'core-api-smoke', '-ldl'])
        shutil.copy2(ROOT / 'src/core-api.h', stage / 'core-api.h')
        native = target == host and platform.machine().lower() in {'x86_64', 'amd64'}
        checks = 'CROSS_COMPILED_NOT_RUN'
        if native:
            for option in ['--version', '--self-test', '--check-components']:
                call([stage / binary, option])
            checks = 'SELF_TEST_AND_COMPONENT_ABI_PASSED'
        files = [{'file': f.name, 'bytes': f.stat().st_size, 'sha256': hashlib.sha256(f.read_bytes()).hexdigest()}
                 for f in sorted(stage.iterdir()) if f.is_file()]
        (stage / 'build-hashes.json').write_text(json.dumps(files, indent=2) + '\n')
        compiler = output([cxx, '--version']).splitlines()[0]
        provenance = {'schema': 'vpn-core-target-build-v1', 'version': version, 'source_commit': commit,
                      'workflow_run': os.environ.get('GITHUB_RUN_ID'), 'workflow_commit': os.environ.get('GITHUB_SHA'), 'source_tree_dirty': dirty, 'target': label, 'host': host,
                      'go': go_version, 'compiler': compiler, 'android_ndk': ndk_version,
                      'android_api': a.android_api if target == 'android' else None,
                      'runtime_checks': checks, 'files': files,
                      'interface': 'SOCKS5 TCP CONNECT + UDP ASSOCIATE; C ABI 2 network hooks; Android JNI/AAR; application-owned TUN',
                      'core_abi': 2, 'source_files_sha256': source_hash.hexdigest()}
        provenance['experimental_netstack'] = a.experimental_netstack
        provenance['packet_abi'] = 1 if a.experimental_netstack else None
        (stage / 'build-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
        destination.mkdir(parents=True, exist_ok=True)
        for f in stage.iterdir(): shutil.copy2(f, destination / f.name)
    print('Built ' + label + ': ' + str(destination))
    call([sys.executable, ROOT / 'scripts/Verify-Target.py', destination])

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', choices=['auto', 'windows', 'linux', 'android'], default='auto')
    p.add_argument('--arch', choices=['amd64'], default='amd64')
    p.add_argument('--abi', choices=list(ANDROID), default='arm64-v8a')
    p.add_argument('--android-api', type=int, default=LOCK['android_api'])
    p.add_argument('--ndk', default=os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT'))
    p.add_argument('--go', default=os.environ.get('VPN_CORE_GO', 'go'))
    p.add_argument('--cc'); p.add_argument('--cxx'); p.add_argument('--output'); p.add_argument('--javac')
    p.add_argument('--require-clean', action='store_true', help='Reject dirty or unverified release source.')
    p.add_argument('--build-tests', action='store_true', help='Also build the target shared-library smoke executable.')
    p.add_argument('--experimental-netstack', action='store_true', help='Opt-in Native TUN device/packet runtime and direct C++ transport probes; route policy remains an embedding responsibility.')
    a = p.parse_args()
    try: build(a)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as e:
        p.exit(1, 'Build failed: ' + str(e) + '\n')

if __name__ == '__main__': main()
