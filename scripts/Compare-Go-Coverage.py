"""Compare original byte-preserved URI support; never publish credentials."""
import argparse,collections,hashlib,json,pathlib,subprocess,tempfile
p=argparse.ArgumentParser();p.add_argument('--baseline',required=True);p.add_argument('--candidate',required=True);p.add_argument('--nodes',required=True);p.add_argument('--report',required=True);a=p.parse_args()
files=[x for x in pathlib.Path(a.nodes).glob('*.txt') if x.name in ('vless.txt','vmess.txt','trojan.txt','shadowsocks.txt')]
report={'schema':'go-migration-coverage-v1','files':[],'total':0,'baseline_supported':0,'candidate_supported':0,'lost_support':0,'semantic_changes':0,'regressions':[]}
keys=['protocol','transport','security','flow','cipher','fingerprint','plugin_mux','websocket_early_data','alter_id','alpn','mode','header_type']
for file in files:
 data=file.read_bytes();uris=[x.strip() for x in data.decode('utf-8-sig').splitlines() if x.strip() and not x.lstrip().startswith('#')]
 with tempfile.TemporaryDirectory() as tmp:
  fixture=pathlib.Path(tmp)/'nodes.txt';fixture.write_text('\n'.join(uris)+'\n',encoding='utf8')
  rows=[]
  for binary in (a.baseline,a.candidate):
   r=subprocess.run([binary,'--inspect-list',str(fixture)],text=True,encoding='utf8',capture_output=True,check=True,timeout=240)
   rows.append([json.loads(line) for line in r.stdout.splitlines()]);assert len(rows[-1])==len(uris)
  counts=collections.Counter()
  for uri,old,new in zip(uris,*rows):
   node=hashlib.sha256(uri.encode()).hexdigest()[:20];assert old['node_id']==new['node_id']==node
   supported=bool(old.get('connectable_by_this_build'));candidate=bool(new.get('connectable_by_this_build'));counts['total']+=1;counts['baseline_supported']+=supported;counts['candidate_supported']+=candidate
   if supported and not candidate:counts['lost_support']+=1;report['regressions'].append({'source':file.name,'node_id':node,'kind':'lost_support','reason':new.get('reason_code')})
   changed=[k for k in keys if old.get(k,[])!=new.get(k,[])]
   if supported and candidate and changed:counts['semantic_changes']+=1;report['regressions'].append({'source':file.name,'node_id':node,'kind':'semantics','fields':changed})
  for k,v in counts.items():report[k]+=v
  report['files'].append({'source':file.name,'sha256':hashlib.sha256(data).hexdigest(),**counts})
pathlib.Path(a.report).write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps({k:v for k,v in report.items() if k not in ('regressions','files')},indent=2))
raise SystemExit(bool(report['lost_support'] or report['semantic_changes']))
