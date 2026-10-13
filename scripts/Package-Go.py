"""Package only manifest-listed Go runtime files and their licenses."""
import argparse,pathlib,json,hashlib,zipfile
p=argparse.ArgumentParser();p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,default=pathlib.Path('dist'));a=p.parse_args();root=pathlib.Path(__file__).resolve().parents[1]
meta=json.loads((a.build/'build-provenance.json').read_text());a.output.mkdir(parents=True,exist_ok=True);output=a.output/f"vpn-core-{meta['version']}-{meta['target']}-{meta['arch']}.zip"
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as z:
 for item in meta['files']:
  path=pathlib.PurePosixPath(item['file']);assert not path.is_absolute() and path.parts and all(part not in ('.','..') for part in path.parts)
  source=(a.build/path).resolve();assert source.is_relative_to(a.build.resolve());data=source.read_bytes();assert len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256'];z.writestr(path.as_posix(),data)
 for name in ['build-provenance.json','build-hashes.json']:z.write(a.build/name,name)
 z.write(root/'docs/GO-NATIVE-CORE.md','GO-NATIVE-CORE.md')
 if not any(item['file'].startswith('licenses/') for item in meta['files']):
  for folder in ['vendor','core/thirdparty','third_party']:
   for f in (root/folder).rglob('*'):
    if f.is_file() and f.name.lower().startswith(('license','notice','copying')):z.write(f,'licenses/'+f.relative_to(root).as_posix())
print(output)
