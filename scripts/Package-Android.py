"""Build an Android AAR from source-built native libraries (one or more ABIs)."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
ABIS={'arm64-v8a','armeabi-v7a','x86_64','x86'}
def archive(path, entries):
    with zipfile.ZipFile(path,'w') as z:
        for name,data in sorted(entries.items()):
            info=zipfile.ZipInfo(name);info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,data)
def package(builds, output, version, javac='javac', api=23):
    entries={};labels=[];native=[]
    for abi,folder in builds:
        if abi not in ABIS or abi in labels:raise ValueError('Invalid or duplicate Android ABI')
        labels.append(abi)
        for name in ['libvpn-core.so','libvpn-tls.so','libvpn-jni.so']:
            data=(folder/name).read_bytes();entries['jni/'+abi+'/'+name]=data
            native.append({'abi':abi,'file':name,'sha256':hashlib.sha256(data).hexdigest()})
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td);classes=td/'classes';classes.mkdir()
        sources=sorted((ROOT/'sdk/android/src').rglob('*.java'))
        subprocess.run([javac,'--release','8','-encoding','UTF-8','-d',str(classes),*[str(s) for s in sources]],check=True)
        jar=td/'classes.jar';archive(jar,{p.relative_to(classes).as_posix():p.read_bytes() for p in classes.rglob('*.class')})
        entries['classes.jar']=jar.read_bytes()
    entries['AndroidManifest.xml']=f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.noorelmostafa.vpncore"><uses-sdk android:minSdkVersion="{api}"/></manifest>\n'.encode()
    entries['R.txt']=b''
    entries['proguard.txt']=b'-keep class com.noorelmostafa.vpncore.NativeCore { *; }\n-keep interface com.noorelmostafa.vpncore.NativeCore$NetworkHooks { *; }\n-keep class * implements com.noorelmostafa.vpncore.NativeCore$NetworkHooks { *; }\n'
    entries['assets/vpn-core/sdk.json']=(json.dumps({'version':version,'core_abi':2,'abis':sorted(labels),'native_files':native},indent=2)+'\n').encode()
    for name in ['NOTICE.md','docs/SDK-INTEGRATION.md']:
        entries['META-INF/vpn-core/'+pathlib.Path(name).name]=(ROOT/name).read_bytes()
    for directory in ['tls-provider/vendor','tls-provider/thirdparty','third_party']:
        for file in (ROOT/directory).rglob('*'):
            if file.is_file() and (directory=='third_party' or file.name.lower().startswith(('license','copying','notice')) or file.name=='sources.json'):
                entries['META-INF/vpn-core/'+file.relative_to(ROOT).as_posix()]=file.read_bytes()
    output.parent.mkdir(parents=True,exist_ok=True);archive(output,entries)
    with zipfile.ZipFile(output) as z:
        if z.testzip():raise ValueError('AAR CRC mismatch')
    return output
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',action='append',required=True);p.add_argument('--output',required=True)
    p.add_argument('--abi',choices=sorted(ABIS));p.add_argument('--version');p.add_argument('--min-sdk',type=int,default=23);p.add_argument('--javac',default='javac');a=p.parse_args()
    builds=[];version=a.version;api=a.min_sdk;source=None
    for text in a.build:
        folder=pathlib.Path(text)
        if a.abi:
            if len(a.build)!=1 or not version:p.error('Staging requires one --build, --abi and --version')
            builds.append((a.abi,folder))
        else:
            subprocess.run([os.sys.executable,str(ROOT/'scripts/Verify-Target.py'),str(folder)],check=True)
            meta=json.loads((folder/'build-provenance.json').read_text());abi=meta['target'].removeprefix('android-')
            if abi not in ABIS or version is not None and version!=meta['version']:p.error('Android AAR inputs must have the same version')
            version=meta['version'];api=max(api,meta['android_api']);builds.append((abi,folder))
            fingerprint=meta.get('source_files_sha256')
            if not fingerprint or source is not None and source!=fingerprint:p.error('Android AAR inputs must come from identical SDK source bytes')
            source=fingerprint
    print('Packaged '+str(package(builds,pathlib.Path(a.output),version,a.javac,api)))
if __name__=='__main__':main()
