"""Bounded HTTPS concurrency against one explicitly supplied node; no credentials in reports."""
import argparse,concurrent.futures,collections,json,os,pathlib,shutil,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--config',type=pathlib.Path,required=True)
p.add_argument('--binary',type=pathlib.Path,default=ROOT/'bin'/('vpn-core.exe' if os.name=='nt' else 'vpn-core'))
p.add_argument('--requests',type=int,default=32);p.add_argument('--concurrency',type=int,default=16)
p.add_argument('--url',default='https://1.1.1.1/cdn-cgi/trace');p.add_argument('--output',type=pathlib.Path,default=ROOT/'build/live-concurrency.json')
a=p.parse_args()
if not (1<=a.concurrency<=64 and a.concurrency<=a.requests<=512 and a.url.startswith('https://')):p.error('HTTPS only; concurrency 1..64, requests up to 512')
binary=a.binary.resolve();curl=shutil.which('curl.exe' if os.name=='nt' else 'curl')
if not curl:p.error('curl required')
options={}
for line in a.config.read_text(encoding='utf-8-sig').splitlines():
 if line.strip() and not line.lstrip().startswith(('#',';')):
  key,_,value=line.partition('=');options[key.strip().lower()]=value.strip()
if 'node_uri' not in options:p.error('node_uri missing')
results=[];events=[]
with tempfile.TemporaryDirectory(prefix='vpn-live-concurrency-') as directory:
 folder=pathlib.Path(directory);ready=folder/'ready.json';config=folder/'node.ini';log=folder/'core.log'
 settings={k:v for k,v in options.items() if k in ('node_uri','test_ca_file','tls_ca_file')}
 settings.update(listen_port='0',max_connections='128',connect_timeout_ms='10000',idle_timeout_ms='15000',ready_file=str(ready))
 config.write_text(''.join(f'{k}={v}\n' for k,v in settings.items()),encoding='utf-8')
 with log.open('w',encoding='utf-8') as stream:
  process=subprocess.Popen([str(binary),'--config',str(config)],stdout=stream,stderr=subprocess.STDOUT)
  try:
   until=time.monotonic()+10;port=None
   while port is None:
    if process.poll() is not None:raise RuntimeError('Core stopped before readiness; configuration or startup failure')
    try:port=json.loads(ready.read_text())['port']
    except (OSError,ValueError,KeyError):
     if time.monotonic()>until:raise RuntimeError('Core readiness timeout')
     time.sleep(.03)
   def request(index):
    started=time.perf_counter()
    run=subprocess.run([curl,'--silent','--noproxy','','--proxy',f'socks5h://127.0.0.1:{port}','--connect-timeout','10','--max-time','20','--output',os.devnull,'--write-out','%{http_code}',a.url],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    return {'index':index,'curl_exit':run.returncode,'http_status':int(run.stdout.strip() or '0'),'duration_ms':round((time.perf_counter()-started)*1000,3)}
   started=time.perf_counter()
   with concurrent.futures.ThreadPoolExecutor(max_workers=a.concurrency) as pool:results=list(pool.map(request,range(a.requests)))
   duration=time.perf_counter()-started
   time.sleep(.05)
  finally:
   process.terminate()
   try:process.wait(5)
   except subprocess.TimeoutExpired:process.kill();process.wait()
 for line in log.read_text(encoding='utf-8',errors='replace').splitlines():
  try:row=json.loads(line)
  except ValueError:continue
  events.append({k:row[k] for k in ('event','reason_code','active_connections','connection_limit','protocol','transport','uploaded_bytes','downloaded_bytes') if k in row})
passed=sum(r['curl_exit']==0 and 200<=r['http_status']<300 for r in results)
timings=sorted(r['duration_ms'] for r in results)
report={'schema':'vpn-live-concurrency-v1','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'requests':a.requests,'concurrency':a.concurrency,'certificate_verification':True,'passed':passed,'failed':len(results)-passed,'duration_seconds':round(duration,3),'request_p50_ms':timings[len(timings)//2],'request_p95_ms':timings[min(len(timings)-1,int(len(timings)*.95))],'peak_active':max((e.get('active_connections',0) for e in events),default=0),'core_reasons':dict(collections.Counter(e['reason_code'] for e in events if 'reason_code' in e)),'results':results}
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
raise SystemExit(passed!=a.requests)
