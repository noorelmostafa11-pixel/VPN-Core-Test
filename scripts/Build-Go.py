"""Build the Go core; a single executable is the default output."""
import argparse,hashlib,json,os,pathlib,platform,shutil,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
ANDROID={'arm64-v8a':('arm64','aarch64-linux-android'),'armeabi-v7a':('arm','armv7a-linux-androideabi'),'x86_64':('amd64','x86_64-linux-android'),'x86':('386','i686-linux-android')}
def call(args,**kw):subprocess.run([str(x) for x in args],check=True,cwd=ROOT,**kw)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--target',default='auto',choices=['auto','windows','linux','darwin','android','freebsd','openbsd']);p.add_argument('--arch',default=platform.machine().lower());p.add_argument('--abi',default='arm64-v8a',choices=ANDROID);p.add_argument('--ndk',default=os.environ.get('ANDROID_NDK_HOME'));p.add_argument('--android-api',type=int,default=23);p.add_argument('--output',type=pathlib.Path);p.add_argument('--go',default='go');p.add_argument('--cc');p.add_argument('--shared',action='store_true');p.add_argument('--wintun',action='store_true');p.add_argument('--require-clean',action='store_true');a=p.parse_args()
 target={'Windows':'windows','Linux':'linux','Darwin':'darwin'}.get(platform.system()) if a.target=='auto' else a.target
 if not target:p.error('select an explicit target')
 arch={'x86_64':'amd64','aarch64':'arm64','x86':'386','armv7l':'arm'}.get(a.arch,a.arch)
 if target=='android':arch,triple=ANDROID[a.abi]
 if arch not in ('amd64','arm64','arm','386'):p.error('supported architectures: amd64, arm64, arm, 386')
 output=(a.output or ROOT/'build'/f'{target}-{arch}').resolve();output.mkdir(parents=True,exist_ok=True)
 env={**os.environ,'CGO_ENABLED':'0','GOOS':target,'GOARCH':arch,'GOWORK':'off'}
 if arch=='arm':env['GOARM']='7'
 call(['python' if os.name=='nt' else 'python3','scripts/Apply-Go-Component-Patches.py'])
 version=subprocess.check_output([a.go,'version'],text=True).strip()
 commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip();dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True))
 if a.require_clean and dirty:p.error('release builds require a clean checkout')
 exe='vpn-core.exe' if target=='windows' else 'vpn-core'
 call([a.go,'build','-mod=vendor','-trimpath','-ldflags=-s -w','-o',output/exe,'./cmd/vpn-core'],env=env)
 if a.shared:
  env['CGO_ENABLED']='1'
  if a.cc:env['CC']=a.cc
  if target=='android':
   if not a.ndk:p.error('--shared Android requires --ndk or ANDROID_NDK_HOME')
   host='windows-x86_64' if os.name=='nt' else 'darwin-x86_64' if platform.system()=='Darwin' else 'linux-x86_64';clang=pathlib.Path(a.ndk)/'toolchains/llvm/prebuilt'/host/'bin'/('clang.exe' if os.name=='nt' else 'clang');env['CC']=f'"{clang}" --target={triple}{a.android_api}';env['CGO_LDFLAGS']='-Wl,-z,max-page-size=16384'
  shared='vpn-core.dll' if target=='windows' else 'libvpn-core.dylib' if target=='darwin' else 'libvpn-core.so'
  call([a.go,'build','-mod=vendor','-trimpath','-buildmode=c-shared','-ldflags=-s -w','-o',output/shared,'./cmd/vpn-shared'],env=env)
 if a.wintun:
  if target!='windows':p.error('--wintun requires Windows target')
  call(['python','scripts/Get-Wintun.py','--build',output,'--arch',arch])
 for name in ('NOTICE.md','OWNERSHIP.md'):shutil.copy2(ROOT/name,output/name)
 allowed={exe,'NOTICE.md','OWNERSHIP.md'}
 if a.shared:allowed.update({shared,pathlib.Path(shared).with_suffix('.h').name})
 if a.wintun:allowed.update({'wintun.dll','WINTUN-LICENSE.txt'})
 files=[{'file':x.name,'bytes':x.stat().st_size,'sha256':hashlib.sha256(x.read_bytes()).hexdigest()} for x in output.iterdir() if x.is_file() and x.name in allowed]
 meta={'version':'0.5.0-go','target':target,'arch':arch,'go':version,'source_commit':commit,'source_tree_dirty':dirty,'files':sorted(files,key=lambda x:x['file'])}
 (output/'build-provenance.json').write_text(json.dumps(meta,indent=2)+'\n');(output/'build-hashes.json').write_text(json.dumps(meta['files'],indent=2)+'\n');print('Built',output)
if __name__=='__main__':main()
