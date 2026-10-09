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
print('HASH_VERIFIED: signed upstream Wintun 0.14.1 ZIP')
