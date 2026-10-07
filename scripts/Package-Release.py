"""Make a complete Windows distribution with original source, licenses and build provenance."""
import argparse,hashlib,json,os,pathlib,zipfile
p=argparse.ArgumentParser();p.add_argument('--output',default='dist');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];version=(root/'VERSION').read_text().strip();files={}
for folder in ['src','scripts','tests','tls-provider','third_party','nodes/pre/protocols']:
    for file in (root/folder).rglob('*'):
        if file.is_file() and '__pycache__' not in file.parts and file.suffix not in {'.pyc','.log'}:
            files[file.relative_to(root).as_posix()]=file.read_bytes()
for name in ['BASELINE-0.4.2.json','COMPONENTS.md','PROTOCOL-SOURCES.md','REPAIRS-0.4.2.md','SUPPORT-0.4.0.md','REPAIRS-0.4.3.md','RELEASE-NOTES.md','pre-source-manifest.json']:
    files['docs/'+name]=(root/'docs'/name).read_bytes()
for name in ['README.md','OWNERSHIP.md','NOTICE.md','VERSION','.gitignore']:
    files[name]=(root/name).read_bytes()
hashes=json.loads((root/'bin/build-hashes.json').read_text(encoding='utf-8-sig'))
for name in ['vpn-core.exe','vpn-tls.dll','vpn-tls.h','build-hashes.json']:
    data=(root/'bin'/name).read_bytes();files['bin/'+name]=data
    if name in {'vpn-core.exe','vpn-tls.dll'}:
        entries=[e for e in hashes if e['file']==name]
        if len(entries)!=1 or entries[0]['sha256']!=hashlib.sha256(data).hexdigest() or entries[0]['bytes']!=len(data):raise SystemExit('Build manifest mismatch: '+name)
for name in ['vpn-core.exe','vpn-tls.dll']:
    if not files['bin/'+name]:raise SystemExit('Empty release binary')
provenance={'schema':'vpn-core-build-provenance-v1','version':version,'source_commit':os.environ.get('GITHUB_SHA','NOT_VERIFIED'),'workflow_run':os.environ.get('GITHUB_RUN_ID','NOT_VERIFIED'),'platform':'windows-amd64','android':'NOT_BUILT','go':'1.27.1','files':hashes}
files['build-provenance.json']=(json.dumps(provenance,indent=2)+'\n').encode()
manifest={'schema':'vpn-core-package-v3','version':version,'source_commit':provenance['source_commit'],'files':[{'path':n,'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()} for n,d in sorted(files.items())],'manifest_exclusions':['package-manifest.json']}
files['package-manifest.json']=(json.dumps(manifest,indent=2)+'\n').encode()
output=pathlib.Path(a.output);output.mkdir(parents=True,exist_ok=True);archive=output/('vpn-core-'+version+'-windows-amd64.zip')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for name,data in sorted(files.items()):z.writestr('vpn-core-'+version+'/'+name,data)
with zipfile.ZipFile(archive) as z:
    if z.testzip() is not None:raise SystemExit('Release ZIP CRC failure')
    for entry in manifest['files']:
        if hashlib.sha256(z.read('vpn-core-'+version+'/'+entry['path'])).hexdigest()!=entry['sha256']:raise SystemExit('Release ZIP hash failure')
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
(output/(archive.name+'.sha256')).write_text(digest+'  '+archive.name+'\n',encoding='utf-8')
print('HASH_VERIFIED: '+archive.name+', '+str(len(manifest['files']))+' complete package files, sha256='+digest)
