"""Retrieve unchanged baseline URI files at the recorded source commit/hash."""
import hashlib,json,pathlib,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
manifest=json.loads((ROOT/'docs/pre-source-manifest.json').read_text())
directory=ROOT/'nodes/pre/protocols';directory.mkdir(parents=True,exist_ok=True)
for row in manifest['files']:
    url='https://raw.githubusercontent.com/'+manifest['repository']+'/'+manifest['commit']+'/output/protocols/'+row['name']
    data=urllib.request.urlopen(url,timeout=120).read()
    if len(data)!=row['bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:raise SystemExit('Pinned URI inventory integrity failed')
    target=directory/row['name']
    if target.exists() and target.read_bytes()!=data:raise SystemExit('Refusing to replace a different node inventory')
    target.write_bytes(data)
print('HASH_VERIFIED: pinned original corpus, '+str(sum(r['nodes'] for r in manifest['files']))+' records')
