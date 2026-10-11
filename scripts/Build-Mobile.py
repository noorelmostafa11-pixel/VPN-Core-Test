"""Build native Android AAR or Apple XCFramework bindings from the Go SDK."""
import argparse,os,pathlib,subprocess,shutil,tempfile,json
ROOT=pathlib.Path(__file__).resolve().parents[1];VERSION='v0.0.0-20261011034528-197770444867'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--target',default='android/arm64');p.add_argument('--output',type=pathlib.Path,default=ROOT/'dist/vpn-core.aar');p.add_argument('--android-api',type=int,default=23);a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True)
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
 for module in ['github.com/refraction-networking/utls','github.com/quic-go/quic-go']:
  info=json.loads(subprocess.check_output(['go','list','-mod=mod','-m','-json',module],cwd=ROOT,text=True))
  destination=stage/'components'/module;shutil.copytree(ROOT/'vendor'/module,destination)
  shutil.copy2(info['GoMod'],destination/'go.mod')
  subprocess.run(['go','mod','edit','-replace='+module+'='+destination.as_posix()],cwd=stage,check=True)
 stage_env={**env,'GOFLAGS':'-mod=mod','GOWORK':'off'}
 subprocess.run(['gomobile','bind','-target',a.target,'-androidapi',str(a.android_api),'-ldflags=-s -w','-o',str(a.output.resolve()),'./mobile'],cwd=stage,env=stage_env,check=True)
print('Built',a.output)
