"""Run the .NET C ABI adapter against the source-built Go shared library."""
import argparse,os,pathlib,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def run(args):subprocess.run([str(a) for a in args],check=True)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',required=True);p.add_argument('--java-only',action='store_true');p.add_argument('--dotnet-only',action='store_true');a=p.parse_args()
    if a.java_only:p.error('Android/Java now uses the Go AAR from scripts/Build-Mobile.py')
    build=pathlib.Path(a.build).resolve();windows=os.name=='nt'
    with tempfile.TemporaryDirectory(prefix='vpn-sdk-') as td:
        td=pathlib.Path(td);cfg=td/'node-مرحبا.ini';cfg.write_text('node_uri=vless://12345678-1234-4567-9234-567812345678@bootstrap.invalid:443?security=none&type=raw\nlisten_port=0\nconnect_timeout_ms=1000\n',encoding='utf-8')
        output=td/'dotnet'
        run(['dotnet','build',ROOT/'tests/dotnet/SdkSmoke.csproj','-o',output])
        shutil.copy2(build/('vpn-core.dll' if windows else 'libvpn-core.so'),output/'vpn-core.dll')
        run(['dotnet',output/'SdkSmoke.dll',cfg])
if __name__=='__main__':main()
