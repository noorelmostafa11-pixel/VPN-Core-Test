"""Reject unbundled non-system PE imports; do not depend on a build host PATH."""
import argparse,pathlib,re,subprocess,json
p=argparse.ArgumentParser();p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--objdump',default='objdump');a=p.parse_args()
os_dlls={'kernel32.dll','kernelbase.dll','ntdll.dll','msvcrt.dll','ucrtbase.dll','ws2_32.dll','secur32.dll','crypt32.dll','bcrypt.dll','iphlpapi.dll','fwpuclnt.dll','rpcrt4.dll','advapi32.dll','user32.dll','shell32.dll','setupapi.dll','cfgmgr32.dll','wintrust.dll','shlwapi.dll','ole32.dll','oleaut32.dll','version.dll','userenv.dll','nsi.dll','normaliz.dll','dnsapi.dll','cryptbase.dll'}
bundled={p.name.lower() for p in a.build.iterdir()};rows=[]
for path in sorted(a.build.iterdir()):
    if path.suffix.lower() not in {'.dll','.exe'}:continue
    output=subprocess.check_output([a.objdump,'-p',str(path)],text=True);imports=re.findall(r'DLL Name:\s*(\S+)',output)
    if not imports:raise SystemExit('No readable PE imports: '+path.name)
    missing=[name for name in imports if name.lower() not in os_dlls|bundled and not name.lower().startswith(('api-ms-win-','ext-ms-win-'))]
    if missing:raise SystemExit('Unbundled non-system DLL imports in '+path.name+': '+', '.join(missing))
    rows.append({'file':path.name,'imports':imports,'status':'PASS'})
print(json.dumps({'status':'PASS','tests':rows}))
