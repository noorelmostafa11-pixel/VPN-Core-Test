"""Package exactly one source-built runtime target, with hashes and licenses."""
import argparse, hashlib, json, pathlib, zipfile, subprocess, sys
p=argparse.ArgumentParser();p.add_argument('--build',required=True);p.add_argument('--output',default='dist');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];build=pathlib.Path(a.build)
subprocess.run([sys.executable,str(root/'scripts/Verify-Target.py'),str(build)],check=True)
provenance=json.loads((build/'build-provenance.json').read_text())
manifest=json.loads((build/'build-hashes.json').read_text())
files={}
for e in manifest:
    path=pathlib.PurePosixPath(e['file'])
    if len(path.parts)!=1 or path.name in {'.','..'}:raise SystemExit('Invalid build manifest path')
    data=(build/path.name).read_bytes()
    if len(data)!=e['bytes'] or hashlib.sha256(data).hexdigest()!=e['sha256']:raise SystemExit('Build hash mismatch: '+path.name)
    files[path.name]=data
for name in ['build-hashes.json','build-provenance.json']:files[name]=(build/name).read_bytes()
for name in ['NOTICE.md','OWNERSHIP.md','docs/BUILDING.md','docs/COMPONENTS.md','docs/SDK-INTEGRATION.md','sdk/windows/VpnCore.cs']:files[name]=(root/name).read_bytes()
for folder in ['tls-provider/vendor','tls-provider/thirdparty']:
    for f in (root/folder).rglob('*'):
        if f.is_file() and (f.name.lower().startswith(('license','copying','notice')) or f.name=='sources.json'):
            files[f.relative_to(root).as_posix()]=f.read_bytes()
for f in (root/'third_party').rglob('*'):
    if f.is_file():files[f.relative_to(root).as_posix()]=f.read_bytes()
out=pathlib.Path(a.output);out.mkdir(parents=True,exist_ok=True)
archive=out/('vpn-core-'+provenance['version']+'-'+provenance['target']+'.zip')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for name,data in sorted(files.items()):
        info=zipfile.ZipInfo(name);info.compress_type=zipfile.ZIP_DEFLATED
        if (build/name).is_file():info.external_attr=((build/name).stat().st_mode & 0xFFFF)<<16
        z.writestr(info,data)
with zipfile.ZipFile(archive) as z:
    if z.testzip():raise SystemExit('Package CRC mismatch')
(out/(archive.name+'.sha256')).write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
print('Packaged '+str(archive))
