"""Verify manifest bytes and Android ELF architecture/page alignment."""
import argparse,hashlib,json,pathlib,struct,zipfile
p=argparse.ArgumentParser();p.add_argument('build');a=p.parse_args();root=pathlib.Path(a.build)
meta=json.loads((root/'build-provenance.json').read_text())
manifest=json.loads((root/'build-hashes.json').read_text())
if manifest!=meta['files']:raise SystemExit('Manifest/provenance file list mismatch')
for e in manifest:
    path=pathlib.PurePosixPath(e['file'])
    if len(path.parts)!=1 or path.name in {'.','..'}:raise SystemExit('Invalid manifest path')
    f=root/e['file'];data=f.read_bytes()
    if len(data)!=e['bytes'] or hashlib.sha256(data).hexdigest()!=e['sha256']:raise SystemExit('Hash mismatch: '+e['file'])
    if meta['target'].startswith('android-') and f.suffix=='.aar':
        abi=meta['target'][8:]
        with zipfile.ZipFile(f) as z:
            if z.testzip() or 'classes.jar' not in z.namelist() or 'proguard.txt' not in z.namelist():raise SystemExit('Invalid Android AAR')
            sdk=json.loads(z.read('assets/vpn-core/sdk.json'))
            if z.read('META-INF/vpn-core/NDK-NOTICE.txt')!=(root/'NDK-NOTICE.txt').read_bytes():raise SystemExit('NDK notice missing or mismatched')
            source=sdk.get('source',{})
            if source.get('commit')!=meta['source_commit'] or source.get('source_files_sha256')!=meta['source_files_sha256'] or source.get('dirty')!=meta['source_tree_dirty']:raise SystemExit('AAR source provenance mismatch')
            if sdk['version']!=meta['version'] or sdk['core_abi']!=2 or sdk['abis']!=[abi]:raise SystemExit('Android AAR SDK metadata mismatch')
            for name in ['libvpn-core.so','libvpn-tls.so','libvpn-jni.so']:
                if z.read('jni/'+abi+'/'+name)!=(root/name).read_bytes():raise SystemExit('Android AAR native library mismatch: '+name)
    if meta['target'].startswith('android-') and (f.suffix=='.so' or f.name=='vpn-core'):
        abi=meta['target'][8:];machine={'arm64-v8a':183,'armeabi-v7a':40,'x86_64':62,'x86':3}[abi]
        if data[:4]!=b'\x7fELF' or data[5]!=1 or struct.unpack_from('<H',data,18)[0]!=machine:raise SystemExit('Android ELF target mismatch')
        is64=data[4]==2
        if is64:
            offset=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
            for i in range(count):
                pos=offset+i*size;kind=struct.unpack_from('<I',data,pos)[0]
                if kind==1 and struct.unpack_from('<Q',data,pos+48)[0]<16384:raise SystemExit('Android 64-bit ELF needs 16 KiB alignment: '+f.name)
print('HASH_VERIFIED: '+meta['target'])
