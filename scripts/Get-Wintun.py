"""Acquire official signed Wintun 0.14.1, verifying the published ZIP hash."""
import argparse,hashlib,pathlib,urllib.request,zipfile,io
p=argparse.ArgumentParser();p.add_argument('--build',type=pathlib.Path,required=True);a=p.parse_args()
url='https://www.wintun.net/builds/wintun-0.14.1.zip';expected='07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
data=urllib.request.urlopen(url,timeout=60).read()
if hashlib.sha256(data).hexdigest()!=expected:raise SystemExit('Wintun ZIP hash mismatch')
a.build.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(io.BytesIO(data)) as z:
    (a.build/'wintun.dll').write_bytes(z.read('wintun/bin/amd64/wintun.dll'))
    (a.build/'WINTUN-LICENSE.txt').write_bytes(z.read('wintun/LICENSE.txt'))
import json
provenance=a.build/'build-provenance.json'
if provenance.exists():
    meta=json.loads(provenance.read_text());manifest=list(meta['files'])
    for name in ('wintun.dll','WINTUN-LICENSE.txt'):
        path=a.build/name;entry={'file':name,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        manifest=[e for e in manifest if e['file']!=name]+[entry]
    meta['files']=sorted(manifest,key=lambda x:x['file']);meta['wintun']={'version':'0.14.1','upstream_zip_sha256':expected}
    (a.build/'build-hashes.json').write_text(json.dumps(meta['files'],indent=2)+'\n');provenance.write_text(json.dumps(meta,indent=2)+'\n')
print('HASH_VERIFIED: signed upstream Wintun 0.14.1 ZIP')
