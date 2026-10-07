"""Validate shard coverage and compare sanitized node outcomes by stable source/ID."""
import argparse,collections,csv,gzip,hashlib,json,pathlib
p=argparse.ArgumentParser();p.add_argument('--reports',required=True);p.add_argument('--output',required=True);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];folder=pathlib.Path(a.output);folder.mkdir(parents=True,exist_ok=True)
baseline_meta=json.loads((root/'docs/BASELINE-NETWORK.json').read_text());fixture=root/baseline_meta['sanitized_fixture']
if hashlib.sha256(fixture.read_bytes()).hexdigest()!=baseline_meta['fixture_sha256']:raise SystemExit('Baseline comparison fixture hash mismatch')
with gzip.open(fixture,'rt',encoding='utf-8') as f:before={(r['source'],r['node_id']):r for r in csv.DictReader(f)}
if len(before)!=72767:raise SystemExit('Baseline comparison coverage mismatch')
rows={};shards=[];errors=[];core_hashes=set();commits=set()
for summary in sorted(pathlib.Path(a.reports).rglob('summary.json')):
    s=json.loads(summary.read_text(encoding='utf-8-sig'));source_rows=[]
    records=summary.parent/'results.ndjson'
    if not records.exists():errors.append('Missing records for '+summary.parent.name);continue
    for line in records.read_text(encoding='utf-8-sig').splitlines():
        r=json.loads(line);key=(r['source'],r['node_id']);source_rows.append(r)
        if key in rows:errors.append('Duplicate stable source/ID in reports')
        if key not in before:errors.append('Unknown stable source/ID in reports')
        rows[key]=r
    statuses=collections.Counter(r['status'] for r in source_rows)
    valid=bool(s['completed'] and not s.get('inventory_error') and not s.get('batch_error') and s['inventory']==len(source_rows) and s['selected']==s['finished'] and not statuses['CANCELLED'])
    if not valid:errors.append('Incomplete shard '+summary.parent.name)
    core_hashes.add(s['core_sha256']);commits.add(s.get('source_commit',''))
    shards.append({'artifact':summary.parent.name,'inventory':s['inventory'],'finished':s['finished'],'selected':s['selected'],'runner_failures':s.get('runner_failures'),'valid':valid})
if len(shards)!=15:errors.append('Expected 15 shard reports')
if set(rows)!=set(before):errors.append('Expected exactly all 72767 baseline source/ID pairs')
if len(core_hashes)!=1 or len(commits)!=1:errors.append('Mixed source commits or core hashes')
transitions=collections.Counter();reasons=collections.Counter();runner=collections.Counter();comparison=[]
for key,r in sorted(rows.items()):
    previous=before.get(key,{});old=previous.get('status','MISSING');transitions[old+' -> '+r['status']]+=1
    reasons[r.get('reason_code') or r.get('phase') or r['status']]+=1
    if r.get('runner_reason_code'):runner[r['runner_reason_code']]+=1
    comparison.append({'source':key[0],'node_id':key[1],'before_status':old,'after_status':r['status'],'before_reason':previous.get('reason_code',''),'after_reason':r.get('reason_code',r.get('phase',''))})
report={'schema':'vpn-network-comparison-v1','baseline_run_id':37582872374,'rows':len(rows),'expected_rows':72767,'complete':not errors,'source_commits':sorted(commits),'core_sha256':sorted(core_hashes),'statuses':dict(collections.Counter(r['status'] for r in rows.values())),'transitions':dict(transitions),'reasons':dict(reasons),'runner_reasons':dict(runner),'shards':shards,'errors':sorted(set(errors)),'limitation':baseline_meta['comparison_limit']}
(folder/'network-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
with (folder/'node-comparison.csv').open('w',newline='',encoding='utf-8') as f:
    w=csv.DictWriter(f,fieldnames=['source','node_id','before_status','after_status','before_reason','after_reason']);w.writeheader();w.writerows(comparison)
text=['# Network comparison','',f"Source: {', '.join(sorted(commits))}",f"Complete: {report['complete']}; rows: {len(rows)}/72767",'', '| Transition | Nodes |','| --- | ---: |']
text += ['| '+k+' | '+str(v)+' |' for k,v in sorted(transitions.items())]
text += ['', 'Network transitions are time dependent; they do not alone prove a code fix caused recovery.']
(folder/'network-summary.md').write_text('\n'.join(text)+'\n',encoding='utf-8')
print(json.dumps({'complete':not errors,'rows':len(rows),'statuses':report['statuses'],'runner_reasons':dict(runner),'errors':sorted(set(errors))}))
if errors:raise SystemExit(1)
