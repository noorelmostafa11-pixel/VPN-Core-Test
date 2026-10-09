"""Validate shard coverage and compare sanitized node outcomes by stable source/ID."""
import argparse,collections,csv,gzip,hashlib,importlib.util,json,pathlib
p=argparse.ArgumentParser();p.add_argument('--reports',required=True);p.add_argument('--output',required=True);p.add_argument('--pre-snapshot',type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];folder=pathlib.Path(a.output);folder.mkdir(parents=True,exist_ok=True)
baseline_meta=json.loads((root/'docs/BASELINE-NETWORK.json').read_text());fixture=root/baseline_meta['sanitized_fixture']
if hashlib.sha256(fixture.read_bytes()).hexdigest()!=baseline_meta['fixture_sha256']:raise SystemExit('Baseline comparison fixture hash mismatch')
with gzip.open(fixture,'rt',encoding='utf-8') as f:before={(r['source'],r['node_id']):r for r in csv.DictReader(f)}
if len(before)!=72767:raise SystemExit('Baseline comparison coverage mismatch')
expected=set(before);expected_count=len(before);pre_commit=None;pre_digest=None
if a.pre_snapshot:
    spec=importlib.util.spec_from_file_location('snapshot',root/'scripts/Prepare-Pre-Snapshot.py')
    snapshot=importlib.util.module_from_spec(spec);spec.loader.exec_module(snapshot)
    manifest_path=a.pre_snapshot/'manifest.json';manifest=snapshot.load_manifest(manifest_path)
    pre_commit=manifest['commit'];pre_digest=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    expected=set();expected_count=sum(e['nodes'] for e in manifest['files'])
    for entry in manifest['files']:
        data=(a.pre_snapshot/'protocols'/entry['name']).read_bytes();snapshot.verify(data,entry)
        for text in data.decode('utf-8-sig').splitlines():
            uri=text.strip()
            if uri and not uri.startswith('#'):expected.add((entry['name'],hashlib.sha256(uri.encode()).hexdigest()[:20]))
rows={};shards=[];errors=[];core_hashes=set();commits=set()
for summary in sorted(pathlib.Path(a.reports).rglob('summary.json')):
    s=json.loads(summary.read_text(encoding='utf-8-sig'));source_rows=[]
    if pre_digest:
        shard_manifest=summary.parent/'pre-manifest.json'
        if not shard_manifest.exists() or hashlib.sha256(shard_manifest.read_bytes()).hexdigest()!=pre_digest:errors.append('Mixed or missing Pre source manifest')
    records=summary.parent/'results.ndjson'
    if not records.exists():errors.append('Missing records for '+summary.parent.name);continue
    for line in records.read_text(encoding='utf-8-sig').splitlines():
        r=json.loads(line);key=(r['source'],r['node_id']);source_rows.append(r)
        if key in rows:errors.append('Duplicate stable source/ID in reports')
        if key not in expected:errors.append('Unknown stable source/ID in reports')
        rows[key]=r
    statuses=collections.Counter(r['status'] for r in source_rows)
    valid=bool(s['completed'] and not s.get('inventory_error') and not s.get('batch_error') and s['inventory']==len(source_rows) and s['selected']==s['finished'] and not statuses['CANCELLED'] and not s.get('runner_failures'))
    if not valid:errors.append('Incomplete shard '+summary.parent.name)
    core_hashes.add(s['core_sha256']);commits.add(s.get('source_commit',''))
    shards.append({'artifact':summary.parent.name,'inventory':s['inventory'],'finished':s['finished'],'selected':s['selected'],'runner_failures':s.get('runner_failures'),'valid':valid})
if len(shards)!=15:errors.append('Expected 15 shard reports')
if set(rows)!=expected or len(rows)!=expected_count:errors.append('Expected exactly all selected Pre source/ID pairs')
if len(core_hashes)!=1 or len(commits)!=1:errors.append('Mixed source commits or core hashes')
transitions=collections.Counter();reasons=collections.Counter();runner=collections.Counter();comparison=[]
for key,r in sorted(rows.items()):
    previous=before.get(key,{});old=previous.get('status','MISSING');transitions[old+' -> '+r['status']]+=1
    reasons[r.get('reason_code') or r.get('phase') or r['status']]+=1
    if r.get('runner_reason_code'):runner[r['runner_reason_code']]+=1
    comparison.append({'source':key[0],'node_id':key[1],'before_status':old,'after_status':r['status'],'before_reason':previous.get('reason_code',''),'after_reason':r.get('reason_code',r.get('phase',''))})
report={'schema':'vpn-network-comparison-v1','pre_commit':pre_commit,'baseline_run_id':37582872374,'rows':len(rows),'expected_rows':expected_count,'new_nodes':len(expected-set(before)),'baseline_only_nodes':len(set(before)-expected),'complete':not errors,'source_commits':sorted(commits),'core_sha256':sorted(core_hashes),'statuses':dict(collections.Counter(r['status'] for r in rows.values())),'transitions':dict(transitions),'reasons':dict(reasons),'runner_reasons':dict(runner),'shards':shards,'errors':sorted(set(errors)),'limitation':baseline_meta['comparison_limit']}
report.update(schema='vpn-network-comparison-v2',
              diagnostic_coverage={'with_d1':sum('curl_exit_code' in r for r in rows.values()),
                                   'without_d1':sum('curl_exit_code' not in r for r in rows.values())},
              curl_reasons=dict(collections.Counter(r.get('curl_reason_code','NOT_RECORDED') for r in rows.values())),
              curl_tls_error_classes=dict(collections.Counter(r.get('curl_tls_error_class','NOT_RECORDED') for r in rows.values() if r.get('curl_exit_code')==35)),
              first_core_reasons=dict(collections.Counter(r['first_core_failure']['reason_code'] for r in rows.values() if r.get('first_core_failure'))),
              cleanup_core_reasons=dict(collections.Counter(r['first_cleanup_core_failure']['reason_code'] for r in rows.values() if r.get('first_cleanup_core_failure'))),
              failure_scopes=dict(collections.Counter(r.get('failure_scope','NOT_RECORDED') for r in rows.values())))
group_fields=('protocol','transport','security','flow','fingerprint','curl_tls_error_class')
group_counts=collections.Counter(tuple(r.get(name,'NOT_RECORDED') for name in group_fields) for r in rows.values() if r.get('curl_exit_code')==35)
report['curl_35_groups']=[dict(zip(group_fields,key),nodes=count) for key,count in sorted(group_counts.items())]

# Keep the exact, sanitized 278-node reference independent of a changing Pre.
cohort_meta=json.loads((root/'docs/XRAY-COMPARISON-COHORT.json').read_text())
cohort_path=root/cohort_meta['sanitized_fixture']
if hashlib.sha256(cohort_path.read_bytes()).hexdigest()!=cohort_meta['fixture_sha256']:raise SystemExit('Xray cohort fixture hash mismatch')
with cohort_path.open(newline='',encoding='utf-8') as f:cohort=list(csv.DictReader(f))
cohort_keys={(r['source'],r['node_id']) for r in cohort}
if len(cohort)!=278 or len(cohort_keys)!=278 or cohort_meta['rows']!=278:raise SystemExit('Xray cohort coverage mismatch')
cohort_results=[]
for prior in cohort:
    key=(prior['source'],prior['node_id']);current=rows.get(key)
    cohort_results.append({'source':key[0],'node_id':key[1],'baseline_status':'FAIL',
                           'baseline_reason':prior['baseline_core_reason'],
                           'selected_in_pre':key in expected,'observed':current is not None,
                           'after_status':current['status'] if current else 'MISSING',
                           'after_reason':current.get('reason_code','') if current else '',
                           'curl_reason':current.get('curl_reason_code','NOT_RECORDED') if current else '',
                           'first_core_reason':(current.get('first_core_failure') or {}).get('reason_code','') if current else ''})
report['xray_both_success_cohort']={'baseline_core_run':cohort_meta['core_baseline_run'],
    'xray_success_runs':cohort_meta['xray_success_runs'],'reference_rows':278,
    'selected_in_pre':len(cohort_keys&expected),'observed':len(cohort_keys&set(rows)),
    'absent_from_pre':len(cohort_keys-expected),'missing_selected_results':len((cohort_keys&expected)-set(rows)),
    'statuses':dict(collections.Counter(r['after_status'] for r in cohort_results)),
    'limitation':'Exact original URI identity. Missing rows are not failures or recoveries; recovered PASS rows alone do not establish causality.'}
(folder/'xray-cohort-summary.json').write_text(json.dumps(report['xray_both_success_cohort'],indent=2)+'\n')
with (folder/'xray-cohort-comparison.csv').open('w',newline='',encoding='utf-8') as f:
    w=csv.DictWriter(f,fieldnames=list(cohort_results[0]));w.writeheader();w.writerows(cohort_results)
(folder/'network-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
with (folder/'node-comparison.csv').open('w',newline='',encoding='utf-8') as f:
    w=csv.DictWriter(f,fieldnames=['source','node_id','before_status','after_status','before_reason','after_reason']);w.writeheader();w.writerows(comparison)
text=['# Network comparison','',f"Source: {', '.join(sorted(commits))}",f"Pre: {pre_commit or 'historical snapshot'}",f"Complete: {report['complete']}; rows: {len(rows)}/{expected_count}",'', '| Transition | Nodes |','| --- | ---: |']
text += ['| '+k+' | '+str(v)+' |' for k,v in sorted(transitions.items())]
text += ['', '## Xray reference cohort', '',
         '278 exact original URIs succeeded in both recorded Xray runs and failed in core run 37855491775.',
         '', '| Outcome | Nodes |', '| --- | ---: |']
text += ['| '+k+' | '+str(v)+' |' for k,v in sorted(report['xray_both_success_cohort']['statuses'].items())]
text += ['', 'Missing cohort members are reported separately; see xray-cohort-comparison.csv.']
text += ['', 'Network transitions are time dependent; they do not alone prove a code fix caused recovery.']
(folder/'network-summary.md').write_text('\n'.join(text)+'\n',encoding='utf-8')
print(json.dumps({'complete':not errors,'rows':len(rows),'statuses':report['statuses'],'runner_reasons':dict(runner),'errors':sorted(set(errors))}))
if errors:raise SystemExit(1)
