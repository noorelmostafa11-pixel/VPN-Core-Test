"""Build native Android AAR or Apple XCFramework bindings from the Go SDK."""
import argparse,os,pathlib,subprocess,shutil,tempfile,json,hashlib,zipfile,struct
ROOT=pathlib.Path(__file__).resolve().parents[1];VERSION='v0.0.0-20261011034528-197770444867'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--target',default='android/arm64');p.add_argument('--output',type=pathlib.Path,default=ROOT/'dist/vpn-core.aar');p.add_argument('--android-api',type=int,default=23);p.add_argument('--require-clean',action='store_true');a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True)
dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True))
if a.require_clean and dirty:p.error('release bindings require a clean checkout')
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
def call(args,env=None):subprocess.run(args,cwd=ROOT,env=env,check=True)
call(['go','install','golang.org/x/mobile/cmd/gomobile@'+VERSION]);call(['go','install','golang.org/x/mobile/cmd/gobind@'+VERSION])
gobin=os.environ.get('GOBIN') or str(pathlib.Path(subprocess.check_output(['go','env','GOPATH'],text=True).strip())/'bin');env={**os.environ,'PATH':gobin+os.pathsep+os.environ['PATH']}
if a.target.startswith('android'):env['CGO_LDFLAGS']='-Wl,-z,max-page-size=16384'
call(['python' if os.name=='nt' else 'python3','scripts/Apply-Go-Component-Patches.py']);call(['gomobile','init'],env)
# gomobile generates a temporary module and requires module mode. Its generated
# module must still use our exact reviewed TLS/QUIC patches, never upstream code.
with tempfile.TemporaryDirectory(prefix='vpn-mobile-') as directory:
 stage=pathlib.Path(directory)
 for name in ['core','mobile']:shutil.copytree(ROOT/name,stage/name)
 for name in ['go.mod','go.sum']:shutil.copy2(ROOT/name,stage/name)
 for module in ['github.com/refraction-networking/utls','github.com/quic-go/quic-go','github.com/apernet/hysteria/core/v2','github.com/apernet/hysteria/extras/v2','github.com/apernet/quic-go','golang.zx2c4.com/wireguard']:
  info=json.loads(subprocess.check_output(['go','list','-mod=mod','-m','-json',module],cwd=ROOT,text=True))
  destination=stage/'components'/module;shutil.copytree(ROOT/'vendor'/module,destination)
  shutil.copy2(info['GoMod'],destination/'go.mod')
  subprocess.run(['go','mod','edit','-replace='+module+'='+destination.as_posix()],cwd=stage,check=True)
 stage_env={**env,'GOFLAGS':'-mod=mod','GOWORK':'off'}
 subprocess.run(['gomobile','bind','-target',a.target,'-androidapi',str(a.android_api),'-ldflags=-s -w','-o',str(a.output.resolve()),'./mobile'],cwd=stage,env=stage_env,check=True)
provenance={'schema':'vpn-mobile-build-v1','version':(ROOT/'VERSION').read_text().strip(),'source_commit':commit,'source_tree_dirty':dirty,'target':a.target,'android_api':a.android_api,'gomobile':VERSION,'go':subprocess.check_output(['go','version'],text=True).strip(),'component_patch_manifest_sha256':hashlib.sha256((ROOT/'components/patches/manifest.json').read_bytes()).hexdigest()}
licenses=[ROOT/'NOTICE.md',ROOT/'OWNERSHIP.md']
for folder in ['vendor','core/thirdparty','third_party']:
 licenses.extend(f for f in (ROOT/folder).rglob('*') if f.is_file() and f.name.lower().startswith(('license','notice','copying')))
if a.target.startswith('android'):
 provenance['native_libraries']=[]
 with zipfile.ZipFile(a.output,'a',zipfile.ZIP_DEFLATED) as archive:
  for name in archive.namelist():
   if name.startswith('jni/') and name.endswith('.so'):
    data=archive.read(name);bits=data[4];endian='<' if data[5]==1 else '>'
    offset=struct.unpack_from(endian+('Q' if bits==2 else 'I'),data,32 if bits==2 else 28)[0]
    size,count=struct.unpack_from(endian+'HH',data,54 if bits==2 else 42)
    segments=[]
    for index in range(count):
     header=struct.unpack_from(endian+('IIQQQQQQ' if bits==2 else 'IIIIIIII'),data,offset+index*size)
     if header[0]==1:segments.append(header[-1])
    if not segments or min(segments)<16384:raise RuntimeError('Android native library lacks 16 KB load alignment: '+name)
    provenance['native_libraries'].append({'file':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'minimum_load_alignment':min(segments)})
  for file in licenses:archive.write(file,'assets/vpn-core-licenses/'+file.relative_to(ROOT).as_posix())
  archive.writestr('assets/vpn-core-build.json',json.dumps(provenance,indent=2)+'\n')
else:
 for file in licenses:
  destination=a.output/'licenses'/file.relative_to(ROOT);destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(file,destination)
 (a.output/'build-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
a.output.with_suffix(a.output.suffix+'.build.json').write_text(json.dumps(provenance,indent=2)+'\n')
print('Built',a.output)
