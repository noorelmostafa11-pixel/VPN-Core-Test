"""One build/test entry point for the original main core and the Go branch."""
import argparse, os, pathlib, shutil, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
GO_CORE = (ROOT / 'go.mod').exists()

def run(*args, cwd=ROOT, env=None):
    subprocess.run([str(x) for x in args], cwd=cwd, env=env, check=True)

def python(script, *args):
    run(sys.executable, ROOT / script, *args)

def peers():
    folder = ROOT if GO_CORE else ROOT / 'tls-provider'
    (ROOT / 'bin').mkdir(exist_ok=True)
    for name in ('xhttp-peer', 'ech-peer', 'quic-peer', 'vless-encryption-peer', 'mldsa-signer'):
        source = name.replace('-', '_') + '.go'
        output = ROOT / 'bin' / (name + ('.exe' if os.name == 'nt' else ''))
        run('go', 'build', '-mod=vendor', '-o', output, ROOT / 'tests' / source, cwd=folder)

def runtime():
    target = 'windows' if os.name == 'nt' else 'linux' if sys.platform.startswith('linux') else 'darwin'
    if GO_CORE:
        python('scripts/Apply-Go-Component-Patches.py')
        run('go', 'test', '-race', './core', './mobile')
        python('scripts/Validate-Go.py')
        python('scripts/Build-Go.py', '--shared', *(['--wintun'] if target == 'windows' else []))
        build = ROOT / 'build' / (target + '-amd64' if target == 'windows' else target + '-' + ('arm64' if os.uname().machine == 'arm64' else 'amd64'))
        library = 'vpn-core.dll' if target == 'windows' else 'libvpn-core.dylib' if target == 'darwin' else 'libvpn-core.so'
        shutil.copy2(build / library, ROOT / 'bin' / ('vpn-core.dll' if target == 'windows' else 'libvpn-core.so'))
        if target == 'windows': shutil.copy2(build / 'wintun.dll', ROOT / 'bin' / 'wintun.dll')
        os.environ['VPN_CORE_TEST_BINARY'] = str(ROOT / 'bin' / ('vpn-core.exe' if target == 'windows' else 'vpn-core'))
        suites = ['test_udp_sdk.NetworkHookTests']
        if target != 'darwin': suites.insert(0, 'test_lifecycle_acceptance.LifecycleAcceptanceTests')
        run(sys.executable, '-m', 'unittest', '-v', *suites, cwd=ROOT / 'tests')
        if target in ('windows', 'linux'):
            native = ROOT / 'bin' / ('native-tests.exe' if target == 'windows' else 'native-tests')
            run('go', 'test', '-c', '-o', native, './core')
            env = {**os.environ, 'VPN_CORE_TEST_NATIVE_TUN': '1', 'VPN_CORE_TEST_POLICY_PLAN': '1'}
            case = 'TestWindowsNativeDevice' if target == 'windows' else 'TestLinuxNativeDevice'
            if target == 'linux': run('sudo', 'env', 'VPN_CORE_TEST_NATIVE_TUN=1', native, '-test.run=' + case, '-test.v', '-test.timeout=90s')
            else:
                run(native, '-test.run=' + case, '-test.v', '-test.timeout=90s', env=env)
                run('pwsh', '-NoProfile', '-File', ROOT / 'tests/test_windows_policy.ps1')
                run('pwsh', '-NoProfile', '-File', ROOT / 'tests/test_windows_dual_policy.ps1')
        python('scripts/Package-Go.py', '--build', build)
    else:
        python('scripts/Apply-Component-Patches.py')
        run('go', 'test', '-mod=vendor', '-race', './...', cwd=ROOT / 'tls-provider')
        python('scripts/Build.py', '--target', target, '--require-clean')
        build = ROOT / 'build' / (target + '-amd64')
        os.environ['VPN_CORE_TEST_BINARY'] = str(build / ('vpn-core.exe' if target == 'windows' else 'vpn-core'))
        peers()
        suites = ['test_portable_044.SharedCoreTests', 'test_udp_sdk.UdpSdkTests', 'test_udp_sdk.NetworkHookTests', 'test_lifecycle_acceptance.LifecycleAcceptanceTests', 'test_dns_acceptance.DnsAcceptanceTests', 'test_pre_coverage.PreCoverageTests', 'test_cleanup_policy.CleanupPolicyTests']
        if target == 'linux': suites.insert(0, 'test_portable_044.PortableTransportTests')
        run(sys.executable, '-m', 'unittest', '-v', *suites, cwd=ROOT / 'tests')
        python('scripts/Package-Target.py', '--build', build)

def portable():
    if not GO_CORE: raise SystemExit('Portable matrix belongs to the Go branch')
    for target in ('windows', 'linux', 'darwin', 'freebsd', 'openbsd'):
        for arch in ('amd64', 'arm64'): python('scripts/Build-Go.py', '--target', target, '--arch', arch)
    python('scripts/Build-Go.py', '--target', 'android', '--abi', 'arm64-v8a')

def mobile():
    if GO_CORE:
        python('scripts/Build-Mobile.py', '--target', 'android/arm64', '--output', ROOT / 'dist/vpn-core.aar', '--require-clean')
    else:
        python('scripts/Build.py', '--target', 'android', '--abi', 'arm64-v8a', '--ndk', os.environ['ANDROID_NDK_HOME'], '--require-clean')
        python('scripts/Package-Target.py', '--build', ROOT / 'build/android-arm64-v8a')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('job', choices=('runtime', 'portable', 'mobile'))
    args = parser.parse_args()
    os.environ['PYTHONUTF8'] = '1'
    os.environ['QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING'] = 'true'
    (ROOT / 'bin').mkdir(exist_ok=True)
    if os.name == 'nt':
        git_tools = pathlib.Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/usr/bin'
        os.environ['PATH'] += os.pathsep + str(git_tools)
    os.environ['PYTHONPATH'] = str(ROOT / 'tests')
    {'runtime': runtime, 'portable': portable, 'mobile': mobile}[args.job]()
