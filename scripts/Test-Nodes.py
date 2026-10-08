"""Test original Pre URIs with one selected source-built core; Linux or Windows."""
import argparse,collections,concurrent.futures,hashlib,json,os,pathlib,shutil,subprocess,tempfile,time,urllib.parse

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(a):
    core=pathlib.Path(a.core).resolve();curl=shutil.which(a.curl)
    if not curl:raise ValueError('curl is required')
    target=urllib.parse.urlsplit(a.url)
    if target.scheme!='https' or not target.hostname or target.username is not None or target.password is not None or any(ord(c)<32 for c in a.url):raise ValueError('Use an HTTPS verification URL without credentials')
    inputs=[]
    for source in sorted(pathlib.Path(a.nodes).glob('*.txt')):
        for uri in source.read_text(encoding='utf-8-sig').splitlines():
            uri=uri.strip()
            if uri and not uri.startswith('#'):inputs.append((source.name,uri))
    selected=[v for i,v in enumerate(inputs) if i%a.shards==a.shard]
    if not selected:raise ValueError('Selected shard is empty')
    output=pathlib.Path(a.output);output.mkdir(parents=True,exist_ok=True)
    manifest=pathlib.Path(a.pre_manifest);pre=json.loads(manifest.read_text())
    for entry in pre['files']:
        if digest(pathlib.Path(a.nodes)/entry['name'])!=entry['sha256']:raise ValueError('Pre file hash mismatch')
    shutil.copy2(manifest,output/'pre-manifest.json')
    with tempfile.TemporaryDirectory(prefix='vpn-node-inspect-') as directory:
        path=pathlib.Path(directory)/'original-uris.txt';path.write_text('\n'.join(v[1] for v in selected)+'\n',encoding='utf-8')
        inspected=subprocess.run([core,'--inspect-list',path],capture_output=True,text=True,check=True,timeout=180)
        checks=[json.loads(v) for v in inspected.stdout.splitlines()]
        if len(checks)!=len(selected):raise ValueError('Inspection coverage mismatch')
    def test(item):
        index,(source,uri)=item;check=checks[index]
        row={'source':source,'node_id':hashlib.sha256(uri.encode()).hexdigest()[:20],'status':'FAIL','phase':'CONFIG_INVALID' if check.get('uri_parsed') else 'PARSE_INVALID','reason_code':check.get('reason_code','CONFIG_INVALID'),'http_status':0}
        if row['node_id']!=check['node_id']:raise ValueError('Original URI identity mismatch')
        if not check.get('parsed'):return row
        with tempfile.TemporaryDirectory(prefix='vpn-node-') as directory:
            directory=pathlib.Path(directory);ready=directory/'ready.json';cfg=directory/'node.ini';log=directory/'core.log'
            cfg.write_text(f'node_uri={uri}\nlisten_port=0\nready_file={ready}\nconnect_timeout_ms={int(a.timeout*1000)}\n',encoding='utf-8')
            with log.open('wb') as stream:
                process=subprocess.Popen([core,'--config',cfg],stdout=stream,stderr=subprocess.STDOUT)
                try:
                    end=time.monotonic()+10
                    while not ready.exists():
                        if process.poll() is not None:row.update(phase='STARTUP_FAILED',reason_code='CORE_EXITED_BEFORE_READY');return row
                        if time.monotonic()>=end:row.update(phase='STARTUP_FAILED',reason_code='CORE_READY_TIMEOUT');return row
                        time.sleep(.02)
                    state=json.loads(ready.read_text())
                    if state['pid']!=process.pid or not 0<state['port']<65536:raise ValueError('Core readiness identity mismatch')
                    result=subprocess.run([curl,'--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--noproxy','not-used.invalid','--proxy',f'socks5h://127.0.0.1:{state["port"]}','--connect-timeout',str(a.timeout),'--max-time',str(a.timeout),'--output',str(directory/'body.bin'),'--write-out','%{http_code}|%{size_download}|%{time_total}',a.url],capture_output=True,text=True,timeout=a.timeout+3)
                    fields=result.stdout.strip().split('|');status=int(fields[0]) if len(fields)==3 and fields[0].isdigit() else 0
                    row.update(phase='NETWORK',reason_code='CURL_'+str(result.returncode),http_status=status)
                    if result.returncode==0 and 200<=status<300:row.update(status='PASS',phase='NETWORK',reason_code='HTTP_2XX',bytes=int(fields[1]),duration_ms=round(float(fields[2])*1000,3))
                    elif result.returncode==0:row['reason_code']='HTTP_STATUS'
                except subprocess.TimeoutExpired:row.update(phase='TIMEOUT',reason_code='TIMEOUT')
                except (OSError,ValueError,json.JSONDecodeError):row.update(status='RUNNER_FAILED',phase='RUNNER',reason_code='RUNNER_FAILED')
                finally:
                    process.terminate()
                    try:process.wait(3)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
            if row['status']!='PASS':
                for line in log.read_text(errors='replace').splitlines():
                    if 'diagnostic=' in line:
                        try:event=json.loads(line.split('diagnostic=',1)[1])
                        except json.JSONDecodeError:continue
                        if event.get('event')=='failure':
                            # Deliberate whitelist: never retain raw logs, URIs or error messages.
                            row.update({k:event[k] for k in ['phase','reason_code','native_status','http_status'] if k in event})
            return row
    records=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.concurrency) as pool:
        for row in pool.map(test,enumerate(selected)):records.append(row)
    (output/'results.ndjson').write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in records))
    counts=collections.Counter(r['status'] for r in records)
    summary={'schema':'vpn-node-test-v2','source_commit':a.source_commit,'core_sha256':digest(core),'pre_commit':pre['commit'],'pre_manifest_sha256':digest(manifest),'shard':a.shard,'shards':a.shards,'inventory':len(selected),'total_pre_inventory':len(inputs),'selected':len(selected),'finished':len(records),'completed':len(records)==len(selected),'statuses':dict(counts),'runner_failures':counts['RUNNER_FAILED'],'reasons':dict(collections.Counter(r['reason_code'] for r in records))}
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
    if counts['RUNNER_FAILED']:raise SystemExit(1)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--core',required=True);p.add_argument('--nodes',required=True);p.add_argument('--pre-manifest',required=True);p.add_argument('--output',required=True);p.add_argument('--source-commit',required=True);p.add_argument('--curl',default='curl');p.add_argument('--url',default='https://example.com/');p.add_argument('--timeout',type=int,default=10);p.add_argument('--concurrency',type=int,default=8);p.add_argument('--shard',type=int,default=0);p.add_argument('--shards',type=int,default=15);a=p.parse_args()
    if not 1<=a.timeout<=120 or not 1<=a.concurrency<=32 or not 0<=a.shard<a.shards<=20:p.error('Invalid timeout, concurrency or shard')
    run(a)
if __name__=='__main__':main()
