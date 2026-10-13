import pathlib,json,hashlib,sys
p=pathlib.Path(sys.argv[1]);m=json.loads((p/'build-provenance.json').read_text());
for e in m['files']:
 f=p/e['file'];d=f.read_bytes();assert len(d)==e['bytes'] and hashlib.sha256(d).hexdigest()==e['sha256']
print('HASH_VERIFIED:',m['target'],m['arch'])
