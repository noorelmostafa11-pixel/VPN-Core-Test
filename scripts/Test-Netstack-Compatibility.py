"""Run real packet -> Go stack -> C++ protocol transfers; preserve measurements."""
import argparse
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import time

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=pathlib.Path,required=True)
    p.add_argument('--output',type=pathlib.Path,required=True)
    a=p.parse_args()
    probe=a.build/('netstack-core-probe.exe' if platform.system()=='Windows' else 'netstack-core-probe')
    started=time.time()
    result=subprocess.run([str(probe.resolve())],capture_output=True,text=True,timeout=120)
    a.output.mkdir(parents=True,exist_ok=True)
    (a.output/'probe.log').write_text(result.stdout+result.stderr)
    rows=[json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    required={'TCP_IPV4','TCP_IPV6','UDP_IPV4','UDP_IPV6','CPP_GO_COPY','IN_PROCESS_EXISTING_CPP_ENGINE'}
    ok=result.returncode==0 and required.issubset({r.get('test') for r in rows}) and all(r.get('status')=='PASS' for r in rows)
    provenance=a.build/'build-provenance.json'
    report={'schema':'vpn-netstack-compatibility-v1','status':'PASS' if ok else 'FAIL',
            'host':platform.platform(),'elapsed_seconds':time.time()-started,'returncode':result.returncode,
            'probe_sha256':hashlib.sha256(probe.read_bytes()).hexdigest(),
            'provenance':json.loads(provenance.read_text()) if provenance.exists() else None,
            'tests':rows,'scope':'Actual in-memory IP/TCP/UDP packets plus real loopback C++ VLESS protocol transport; no OS TUN adapter or routing changes.'}
    (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(result.stdout,end='');print(result.stderr,end='',file=sys.stderr)
    if not ok:raise SystemExit('Packet/core compatibility proof failed')

if __name__=='__main__':main()
