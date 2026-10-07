"""Recover only the byte-identical public test snapshot from the existing baseline ZIP."""
import hashlib,json,pathlib,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
archive=ROOT/'VPN-Core-Test-Public-Bundle.zip'
expected='ba3c587921d8b9a8ad6487137eccb71a736f5137039a80d90ebe1535e9f05cfd'
if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:raise SystemExit('Baseline ZIP hash mismatch')
manifest=json.loads((ROOT/'docs/pre-source-manifest.json').read_text(encoding='utf-8-sig'))
total=0
with zipfile.ZipFile(archive) as z:
    for entry in manifest['files']:
        name=entry['name']
        if name not in {'vless.txt','vmess.txt','trojan.txt','shadowsocks.txt'}:raise SystemExit('Unexpected snapshot filename')
        target=ROOT/'nodes/pre/protocols'/name
        data=z.read('nodes/pre/protocols/'+name)
        if len(data)!=entry['bytes'] or hashlib.sha256(data).hexdigest()!=entry['sha256']:raise SystemExit('Snapshot integrity mismatch: '+name)
        count=sum(bool(line.strip()) for line in data.decode('utf-8-sig').splitlines())
        if count!=entry['nodes']:raise SystemExit('Snapshot count mismatch: '+name)
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);total+=count
if total!=72767:raise SystemExit('Snapshot total mismatch')
print('HASH_VERIFIED: pinned public snapshot, 72767 original rows, no URI changes')
