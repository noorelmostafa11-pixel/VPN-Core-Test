"""Verify manifest bytes and Android ELF architecture/page alignment."""
import argparse,hashlib,json,pathlib,struct
p=argparse.ArgumentParser();p.add_argument('build');a=p.parse_args();root=pathlib.Path(a.build)
meta=json.loads((root/'build-provenance.json').read_text())
for e in json.loads((root/'build-hashes.json').read_text()):
    f=root/e['file'];data=f.read_bytes()
    if len(data)!=e['bytes'] or hashlib.sha256(data).hexdigest()!=e['sha256']:raise SystemExit('Hash mismatch: '+e['file'])
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
