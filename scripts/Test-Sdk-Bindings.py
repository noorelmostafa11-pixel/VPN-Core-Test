"""Run Java/JNI and .NET bindings against a native source-built core."""
import argparse,os,pathlib,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def run(args):subprocess.run([str(a) for a in args],check=True)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',required=True);p.add_argument('--java-only',action='store_true');p.add_argument('--dotnet-only',action='store_true');a=p.parse_args()
    build=pathlib.Path(a.build).resolve();windows=os.name=='nt';jni_home=pathlib.Path(os.environ['JAVA_HOME']) if os.environ.get('JAVA_HOME') else None
    with tempfile.TemporaryDirectory(prefix='vpn-sdk-') as td:
        td=pathlib.Path(td);cfg=td/'node-مرحبا.ini';cfg.write_text('node_uri=vless://12345678-1234-4567-9234-567812345678@bootstrap.invalid:443?security=none&type=raw\nlisten_port=0\nconnect_timeout_ms=1000\n',encoding='utf-8')
        if not a.dotnet_only:
            if windows:p.error('JNI host smoke is Linux; Android JNI is built by its NDK target')
            if not jni_home:p.error('Set JAVA_HOME to a JDK 17+ for the JNI host smoke')
            native=td/'native';native.mkdir();classes=td/'classes';classes.mkdir()
            for name in ['libvpn-core.so','libvpn-tls.so']:shutil.copy2(build/name,native/name)
            run([os.environ.get('CXX','g++'),'-std=c++17','-O2','-fPIC','-shared','-Wall','-Wextra','-Wpedantic','-Werror','-Wno-misleading-indentation',
                 ROOT/'sdk/android/jni.cpp','-I'+str(jni_home/'include'),'-I'+str(jni_home/'include/linux'),'-L'+str(native),'-l:libvpn-core.so','-Wl,-rpath,$ORIGIN','-o',native/'libvpn-jni.so'])
            run([jni_home/'bin/javac','--release','8','-d',classes,ROOT/'sdk/android/src/com/noorelmostafa/vpncore/NativeCore.java',ROOT/'tests/java/SdkSmoke.java'])
            run([jni_home/'bin/java','-Djava.library.path='+str(native),'-cp',classes,'SdkSmoke',cfg])
        if not a.java_only:
            output=td/'dotnet'
            run(['dotnet','build',ROOT/'tests/dotnet/SdkSmoke.csproj','-o',output])
            shutil.copy2(build/('vpn-core.dll' if windows else 'libvpn-core.so'),output/'vpn-core.dll')
            provider='vpn-tls.dll' if windows else 'libvpn-tls.so';shutil.copy2(build/provider,output/provider)
            run(['dotnet',output/'SdkSmoke.dll',cfg])
if __name__=='__main__':main()
