"""Assert every original node ID and inspection field stays identical to the selected stable baseline."""
import argparse,hashlib,itertools,json,pathlib,subprocess,tempfile
p=argparse.ArgumentParser();p.add_argument('--baseline',required=True);p.add_argument('--candidate',required=True);p.add_argument('--output',required=True);p.add_argument('--baseline-version',default='0.4.2');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];report={'schema':'vpn-inventory-comparison-v1','baseline_version':a.baseline_version,'candidate_version':(root/'VERSION').read_text().strip(),'sources':[],'rows':0,'changed_rows':0}
for binary,label in [(a.baseline,'baseline'),(a.candidate,'candidate')]:report[label+'_sha256']=hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()
for source in sorted((root/'nodes/pre/protocols').glob('*.txt')):
    with tempfile.TemporaryFile('w+b') as before,tempfile.TemporaryFile('w+b') as after:
        for binary,out in [(a.baseline,before),(a.candidate,after)]:
            subprocess.run([binary,'--inspect-list',str(source)],stdout=out,stderr=subprocess.DEVNULL,check=True,timeout=120);out.seek(0)
        count=0
        for old,new in itertools.zip_longest(before,after):
            if old is None or new is None or json.loads(old)!=json.loads(new):raise SystemExit('Inventory changed: '+source.name+' row '+str(count+1))
            count+=1
        report['rows']+=count;report['sources'].append({'name':source.name,'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'rows':count})
if report['rows']!=72767:raise SystemExit('Inventory total mismatch')
report['status']='PASS';pathlib.Path(a.output).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print('PASS: all 72767 original inspection records and node IDs match baseline '+a.baseline_version)
