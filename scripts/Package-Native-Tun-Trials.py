"""Package only completed experiment evidence and matching clean CI binaries."""
import argparse,hashlib,json,pathlib,shutil,subprocess,tempfile,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def zip_tree(folder,out):
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for path in sorted(folder.rglob('*')):
            if path.is_file():z.write(path,str(path.relative_to(folder.parent)))
def verify(build,sha):
    meta=json.loads((build/'build-provenance.json').read_text())
    if meta['source_commit']!=sha or meta['source_tree_dirty']:raise RuntimeError('Package requires exact clean CI source')
    for entry in json.loads((build/'build-hashes.json').read_text()):
        path=build/entry['file']
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=entry['sha256']:raise RuntimeError('Build integrity mismatch')
    return meta
def main():
    p=argparse.ArgumentParser();p.add_argument('--artifacts',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
    sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip();a.output.mkdir(parents=True,exist_ok=True)
    subprocess.run([__import__('sys').executable,ROOT/'scripts/Report-Native-Tun-Trials.py','--artifacts',a.artifacts,'--output',a.output],cwd=ROOT,check=True)
    source=a.output/('native-tun-source-'+sha[:12]+'.zip')
    subprocess.run(['git','archive','--format=zip','--output='+str(source.resolve()),sha],cwd=ROOT,check=True)
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td)
        for target in ('windows','linux','android'):
            artifact=a.artifacts/('native-tun-'+target+'-'+sha)
            if not artifact.is_dir():raise RuntimeError('Missing completed artifact '+target)
            trial=td/('VPN-Native-TUN-'+target);trial.mkdir();(trial/'SDK').mkdir()
            shutil.copy2(source,trial/source.name)
            for report in ('native-tun-report.json','NATIVE-TUN-REPORT.md'):shutil.copy2(a.output/report,trial/report)
            shutil.copytree(ROOT/'docs',trial/'Docs')
            shutil.copytree(artifact/'evidence',trial/'Evidence')
            if target=='android':
                runtime=trial/'Runtime';runtime.mkdir()
                for build in sorted((artifact/'build').glob('android-*')):
                    verify(build,sha);shutil.copytree(build,runtime/build.name)
                shutil.copy2(artifact/'dist/vpn-core-native-tun-experiment.apk',trial/'vpn-core-native-tun-experiment.apk')
                shutil.copy2(artifact/'dist/vpn-core-native-tun.aar',trial/'vpn-core-native-tun.aar')
                shutil.copytree(ROOT/'sdk/android',trial/'SDK/android')
                instructions='Install the debug experiment APK. Enter the unchanged original node URI, approve VPN access, connect and use Test HTTPS connection. Disconnect explicitly. Enable Android always-on and Block connections without VPN for crash protection. The service integration is supplied as source: include NativeCore, JNI libraries and VpnCoreVpnService in the app with the documented manifest permissions. Test packages use a fresh debug key; uninstall the previous experiment before installing a new build. Existing proxy runStandalone/run APIs remain available.'
            else:
                build=artifact/'build'/('windows-amd64' if target=='windows' else 'linux-amd64');verify(build,sha);shutil.copytree(build,trial/'Core')
                if target=='linux':
                    # Artifact extraction resets file modes; restore executable
                    # bits in the final ZIP and exercise that exact packaged core.
                    for name in ('vpn-core','netstack-core-probe','core-api-smoke'):
                        path=trial/'Core'/name
                        if path.is_file():path.chmod(0o755)
                    for option in ('--version','--self-test','--check-components'):subprocess.run([trial/'Core/vpn-core',option],check=True)
                shutil.copytree(ROOT/'sdk/native',trial/'SDK/native')
                shutil.copytree(ROOT/('sdk/windows' if target=='windows' else 'sdk/linux'),trial/('SDK/windows' if target=='windows' else 'SDK/linux'))
                if target=='windows':
                    shutil.copy2(ROOT/'sdk/windows/Start-Native-Tun.ps1',trial/'Core/Start-Native-Tun.ps1')
                    instructions='Requires Windows 10 build 19041+ or Windows 11 x64 and Administrator. Create node.ini containing node_uri=<your unchanged original URI>. In an elevated Windows PowerShell: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Core\\Start-Native-Tun.ps1 -ConfigPath .\\node.ini. Ctrl+C disconnects and joins. After a crash or fatal error: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Core\\Start-Native-Tun.ps1 -Recover. Existing SOCKS fallback: .\\Core\\vpn-core.exe --config .\\node.ini (after stopping/recovering the tunnel). Required non-system DLLs are bundled and CI checked.'
                else:
                    instructions='Requires x86_64 Ubuntu 24.04 or an ABI-compatible Linux with OpenSSL 3, root/CAP_NET_ADMIN, Python 3.10+, iproute2, nftables and systemd-resolved. Create node.ini with the unchanged URI. Run sudo python3 SDK/linux/native_tun.py --build Core --config node.ini --node-host ORIGINAL_HOST --node-port ORIGINAL_PORT --uplink PHYSICAL_INTERFACE. Ctrl+C disconnects. After a crash: sudo python3 SDK/linux/native_tun.py --recover. The host/port must match the original URI, never rewritten. Legacy proxy fallback: ./Core/vpn-core --config node.ini after stop/recovery.'
            (trial/'README.txt').write_text('EXPERIMENTAL NATIVE TUN TRIAL\nSource: '+sha+'\nStable reference: 0.4.11 / 90a1853114de3e4bcb3deed6747801c10bc5b370\n\n'+instructions+'\n\nSee Docs/NATIVE-TUN-INTEGRATION.md and Evidence for coverage and performance limits. This package is for physical-device acceptance, not production approval. No node URI corpus is published in this package.\n')
            files=[{'file':str(x.relative_to(trial)),'sha256':hashlib.sha256(x.read_bytes()).hexdigest(),'bytes':x.stat().st_size} for x in sorted(trial.rglob('*')) if x.is_file()]
            (trial/'package-hashes.json').write_text(json.dumps(files,indent=2)+'\n')
            zip_tree(trial,a.output/('VPN-Native-TUN-'+target+'-'+sha[:12]+'.zip'))
    print(json.dumps({'status':'PACKAGED','source':sha,'files':[p.name for p in sorted(a.output.iterdir())]}))
if __name__=='__main__':main()
