"""Test original Pre URIs with one selected source-built core; Linux or Windows."""
import argparse,collections,concurrent.futures,hashlib,json,math,os,pathlib,re,shutil,subprocess,tempfile,time,urllib.parse

METRICS='%{http_code}|%{size_download}|%{time_total}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{num_connects}|%{ssl_verify_result}'
DEFAULT_TARGETS=(('example','https://example.com/'),
                 ('google','http://connectivitycheck.gstatic.com/generate_204'),
                 ('microsoft','https://www.microsoft.com/robots.txt'))
PHASES={'SOCKS_FAILED','CONNECT_FAILED','DNS_FAILED','TLS_FAILED','TRANSPORT_FAILED','PROTOCOL_FAILED','RELAY_FAILED','FEATURE_UNIMPLEMENTED','PARSE_INVALID','TIMEOUT','CANCELLED'}
DIAGNOSTIC=re.compile(r'^\[connection ([0-9]{1,20})\] diagnostic=(\{.*\})\s*$')
INSPECTION_SYMBOLS={
    'protocol':{'trojan','vless','vmess','ss'},
    'transport':{'raw','websocket','httpupgrade','grpc','xhttp','http','kcp','quic','obfs-http','obfs-tls'},
    'security':{'none','tls','reality','xtls'},
    'flow':{'','xtls-rprx-vision','xtls-rprx-vision-udp443','xtls-rprx-direct','xtls-rprx-direct-udp443',
            'xtls-rprx-origin','xtls-rprx-origin-udp443','xtls-rprx-splice','xtls-rprx-splice-udp443'},
    'fingerprint':{'','chrome','firefox','safari','ios','android','edge','360','qq','unsafe','native',
                   'random','randomized','randomizednoalpn'}}

def integer(value,minimum=0,maximum=2**63-1):
    return value if type(value) is int and minimum<=value<=maximum else None

def inspection_metadata(check):
    result={}
    for name,allowed in INSPECTION_SYMBOLS.items():
        value=check.get(name)
        result[name]=value if isinstance(value,str) and value in allowed else 'OTHER'
    result['websocket_early_data']=integer(check.get('websocket_early_data'),maximum=16384)
    alpn=check.get('alpn')
    result['alpn']=[value if value in ('h2','http/1.1','h3') else 'OTHER' for value in alpn[:16]] if isinstance(alpn,list) else []
    return result

def curl_tls_groups(records):
    fields=('protocol','transport','security','flow','fingerprint','curl_tls_error_class')
    counts=collections.Counter(tuple(row[name] for name in fields) for row in records if row['curl_exit_code']==35)
    return [dict(zip(fields,key),nodes=count) for key,count in sorted(counts.items())]

def diagnostic(line):
    """Only numeric fields and bounded diagnostic symbols leave the log."""
    if len(line)>8192:return None
    match=DIAGNOSTIC.fullmatch(line)
    if not match:return None
    try:event=json.loads(match[2])
    except (ValueError,TypeError):return None
    if not isinstance(event,dict) or event.get('event') not in ('failure','negotiated'):return None
    connection=integer(int(match[1]),maximum=2**64-1)
    if connection is None:return None
    if 'connection_id' in event and integer(event['connection_id'],maximum=2**64-1)!=connection:return None
    safe={'event':event['event'],'connection_id':connection,
          'timestamp_unix_ms':integer(event.get('timestamp_unix_ms')),
          'tls_version':event.get('tls_version') if event.get('tls_version') in ('TLS1.2','TLS1.3') else '',
          'alpn':event.get('alpn') if event.get('alpn') in ('','h2','http/1.1','h3') else 'OTHER',
          'tunnel_ready':event.get('tunnel_ready') if type(event.get('tunnel_ready')) is bool else None}
    if event['event']=='failure':
        phase=event.get('phase');reason=event.get('reason_code')
        if not isinstance(phase,str) or phase not in PHASES or not isinstance(reason,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}',reason):return None
        native=integer(event.get('native_status',0),maximum=2**32-1)
        http=integer(event.get('http_status',0),maximum=599)
        if native is None or http is None or 0<http<100:return None
        safe.update(phase=phase,reason_code=reason,native_status=native,http_status=http)
    return safe

def read_diagnostics(path,boundary):
    events=[]
    with path.open('rb') as stream:
        while True:
            line=stream.readline(8193)
            if not line:break
            if not line.endswith(b'\n'):
                # Ignore partial or oversized lines; do not parse their tails.
                while line and not line.endswith(b'\n'):line=stream.readline(8193)
                continue
            event=diagnostic(line.decode('utf-8',errors='replace').rstrip('\r\n'))
            if event is not None:
                event['observed_before_cleanup']=stream.tell()<=boundary
                events.append(event)
    return events

def curl_class(code):
    return {0:'OK',7:'CONNECT',28:'TIMEOUT',35:'TLS_HANDSHAKE',52:'EMPTY_RESPONSE',
            56:'RECEIVE',60:'CERTIFICATE_VERIFICATION',77:'LOCAL_CA_FILE',97:'PROXY_HANDSHAKE'}.get(code,
            'NOT_STARTED' if code is None else 'PROCESS_SIGNAL' if code<0 else 'OTHER')

def tls_error_class(code,stderr):
    if code!=35:return 'NOT_APPLICABLE'
    if isinstance(stderr,bytes):stderr=stderr.decode('utf-8',errors='replace')
    message=(stderr or '').lower()
    for phrase,kind in [('wrong version number','TLS_RECORD_VERSION'),
                        ('unexpected eof','TLS_UNEXPECTED_EOF'),
                        ('no application protocol','TLS_ALPN'),
                        ('alert protocol version','TLS_PROTOCOL_VERSION'),
                        ('handshake failure','TLS_HANDSHAKE_FAILURE'),
                        ('certificate verify failed','TLS_CERTIFICATE'),
                        ('ssl_error_syscall','TLS_IO'),('alert','TLS_ALERT_UNCLASSIFIED')]:
        if phrase in message:return kind
    return 'TLS_UNCLASSIFIED'

def curl_metrics(stdout):
    if isinstance(stdout,bytes):stdout=stdout.decode('utf-8',errors='replace')
    fields=(stdout or '').strip().split('|')
    if len(fields) not in (3,8) or not re.fullmatch(r'[0-9]{3}',fields[0]):return {}
    status=int(fields[0])
    if status!=0 and not 100<=status<=599:return {}
    try:
        size=int(fields[1]);seconds=float(fields[2])
        if size<0 or not math.isfinite(seconds) or seconds<0:return {}
        result={'curl_http_status':status,'curl_bytes':size,'curl_duration_ms':round(seconds*1000,3)}
        if len(fields)==8:
            for name,value in zip(('curl_connect_ms','curl_appconnect_ms','curl_starttransfer_ms'),fields[3:6]):
                try:seconds=float(value)
                except (ValueError,OverflowError):continue
                if math.isfinite(seconds) and seconds>=0:result[name]=round(seconds*1000,3)
            for name,value in zip(('curl_num_connects','curl_ssl_verify_result'),fields[6:8]):
                try:number=int(value)
                except (ValueError,OverflowError):continue
                if number>=0:result[name]=number
        return result
    except (ValueError,OverflowError):return {}

def retain_curl(row,code,stdout,stderr,complete=True):
    row.update(curl_exit_code=code,curl_output_complete=complete,curl_error_class=curl_class(code),
               curl_tls_error_class=tls_error_class(code,stderr))
    row.update(curl_metrics(stdout))
    if code is not None:row['curl_reason_code']='CURL_'+str(code)

def retain_core(row,log,boundary):
    events=read_diagnostics(log,boundary)
    failures=[event for event in events if event['event']=='failure']
    before=[event for event in failures if event['observed_before_cleanup'] and event['phase']!='CANCELLED']
    cleanup=[event for event in failures if not event['observed_before_cleanup'] or event['phase']=='CANCELLED']
    ready={event['connection_id'] for event in events if event['observed_before_cleanup'] and
           (event['event']=='negotiated' or event['tunnel_ready'] is True)}
    explicit_not_ready=any(event['tunnel_ready'] is False for event in before)
    row.update(first_core_failure=before[0] if before else None,
               last_core_failure=failures[-1] if failures else None,
               first_cleanup_core_failure=cleanup[0] if cleanup else None,
               cleanup_core_failures=cleanup[:16],cleanup_core_failures_truncated=len(cleanup)>16,
               core_failure_count=len(failures),core_pre_cleanup_failure_count=len(before),
               core_cleanup_failure_count=len(cleanup),core_tunnel_ready_count=len(ready),
               core_tunnel_ready=True if ready else False if explicit_not_ready else None)
    # A chronology is evidence, not proof of the root cause. Retain curl
    # independently; TLS errors after SOCKS must not become outer TLS errors.
    first=row['first_core_failure'];code=row['curl_exit_code']
    if row['status']=='PASS':row['failure_scope']='NONE';return
    if row['status']=='RUNNER_FAILED' or row.get('runner_reason_code'):scope='RUNNER'
    elif row.get('curl_wait_reason'):scope='RUNNER_WAIT'
    elif row['phase']=='STARTUP_FAILED':scope='CORE_STARTUP'
    elif code==0:scope='HTTP_RESPONSE' if row.get('request_scheme')=='http' else 'HTTPS_RESPONSE'
    elif code in (60,83,90,91):scope='HTTPS_CERTIFICATE'
    elif code==77:scope='RUNNER_CONFIGURATION'
    elif code==35:scope='HTTPS_TLS_OR_TUNNEL'
    elif first and first['tunnel_ready'] is False and not ready and code in (7,28,52,56,97):
        scope='OUTER_TUNNEL'
        row.update(phase=first['phase'],reason_code=first['reason_code'],native_status=first['native_status'])
    elif first and ready:scope='RELAY_OR_HTTPS'
    else:scope='NETWORK_UNCLASSIFIED'
    row['failure_scope']=scope
    if scope=='OUTER_TUNNEL':
        row['first_failure']={'source':'CORE','phase':first['phase'],'reason_code':first['reason_code'],
                              'connection_id':first['connection_id'],'basis':'PRE_CLEANUP_FAILURE_BEFORE_TUNNEL_READY'}
    else:
        row['first_failure']={'source':'RUNNER' if row.get('runner_reason_code') else 'CURL' if code is not None else 'CURL_PROCESS' if row['network_test_performed'] else 'CORE_STARTUP',
                              'phase':row['phase'],'reason_code':row['reason_code'],'basis':'PROCESS_WAIT_RESULT' if row.get('curl_wait_reason') else 'REQUEST_RESULT'}

class StartupFailure(Exception):pass

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def verification_targets(a):
    """Keep an explicit HTTPS --url as a single-target compatibility override."""
    url=getattr(a,'url',None)
    if url is None:return DEFAULT_TARGETS
    target=urllib.parse.urlsplit(url)
    if target.scheme!='https' or not target.hostname or target.username is not None or target.password is not None or any(ord(c)<32 for c in url):
        raise ValueError('Use an HTTPS verification URL without credentials')
    return (('custom',url),)

def probe_targets(a,curl,port,directory,targets):
    """Try ordered targets within one deadline; never wait out a successful slot."""
    started=time.monotonic();deadline=started+a.timeout;slot=a.timeout/len(targets)
    attempts=[]
    trust=['--cacert',str(a.curl_cacert)] if getattr(a,'curl_cacert',None) else []
    for endpoint,url in targets:
        budget=min(slot,deadline-time.monotonic())
        if budget<=0:break
        # Give curl a small part of its slot to flush its real exit/metrics.
        # The Python watchdog also shares the global deadline: no extra +3s.
        request_budget=budget-min(.05,budget*.05)
        scheme=urllib.parse.urlsplit(url).scheme
        attempt={'endpoint':endpoint,'request_scheme':scheme,'status':'FAIL','phase':'NETWORK',
                 'reason_code':'CURL_NOT_STARTED','http_status':0,'curl_http_status':0,
                 'curl_exit_code':None,'curl_reason_code':'CURL_NOT_STARTED',
                 'curl_error_class':'NOT_STARTED','curl_tls_error_class':'NOT_APPLICABLE',
                 'curl_output_complete':False,'curl_wait_reason':'',
                 'budget_seconds':round(budget,6)}
        # HTTP is available only for the built-in Google 204 target. HTTPS
        # requests and every redirect continue to prohibit a TLS downgrade.
        allowed='=http,https' if scheme=='http' else '=https'
        try:
            result=subprocess.run([curl,'--disable','--silent','--show-error','--location',
                '--proto',allowed,'--proto-redir','=https','--noproxy','not-used.invalid',
                '--proxy',f'socks5h://127.0.0.1:{port}',
                '--connect-timeout',str(request_budget),'--max-time',str(request_budget),
                '--output',str(directory/'body.bin'),'--write-out',METRICS,*trust,url],
                capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=budget)
            retain_curl(attempt,result.returncode,result.stdout,result.stderr)
            status=attempt['curl_http_status']
            attempt.update(reason_code='CURL_'+str(result.returncode),http_status=status)
            if result.returncode==0 and 200<=status<300:
                attempt.update(status='PASS',reason_code='HTTP_2XX',
                               bytes=attempt['curl_bytes'],duration_ms=attempt['curl_duration_ms'])
            elif result.returncode==0:attempt['reason_code']='HTTP_STATUS'
        except subprocess.TimeoutExpired as error:
            retain_curl(attempt,None,error.stdout,error.stderr,complete=False)
            attempt.update(phase='TIMEOUT',reason_code='TIMEOUT',
                           curl_reason_code='CURL_EXIT_UNAVAILABLE',curl_wait_reason='SUBPROCESS_TIMEOUT')
        except OSError:
            attempt.update(status='RUNNER_FAILED',phase='RUNNER',reason_code='RUNNER_FAILED',
                           runner_reason_code='RUNNER_FAILED')
        attempts.append(attempt)
        if attempt['status'] in ('PASS','RUNNER_FAILED'):break
    # Preserve the first request failure when all targets fail. A successful
    # fallback owns the top-level curl fields; earlier failures stay intact.
    if not attempts:
        return {'status':'FAIL','phase':'TIMEOUT','reason_code':'TIMEOUT','curl_exit_code':None,
                'curl_reason_code':'CURL_EXIT_UNAVAILABLE','curl_wait_reason':'NETWORK_BUDGET_EXHAUSTED',
                'curl_output_complete':False,'probe_attempts':[],'selected_endpoint':'','success_endpoint':'',
                'network_budget_seconds':a.timeout,'network_duration_ms':round((time.monotonic()-started)*1000,3)}
    selected=next((r for r in attempts if r['status'] in ('PASS','RUNNER_FAILED')),attempts[0])
    result={key:value for key,value in selected.items() if key not in ('endpoint','budget_seconds')}
    result.update(probe_attempts=attempts,selected_endpoint=selected['endpoint'],
                  success_endpoint=selected['endpoint'] if selected['status']=='PASS' else '',
                  network_budget_seconds=a.timeout,network_duration_ms=round((time.monotonic()-started)*1000,3))
    return result

def run(a):
    core=pathlib.Path(a.core).resolve();curl=shutil.which(a.curl)
    if not curl:raise ValueError('curl is required')
    targets=verification_targets(a)
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
        row={'source':source,'node_id':hashlib.sha256(uri.encode()).hexdigest()[:20],'status':'FAIL' if check.get('parsed') else 'PARSE_INVALID','phase':'CONFIG_INVALID' if check.get('uri_parsed') else 'PARSE_INVALID','reason_code':check.get('reason_code','CONFIG_INVALID'),'http_status':0}
        row.update(inspection_metadata(check))
        row.update(network_test_performed=False,curl_exit_code=None,curl_reason_code='CURL_NOT_STARTED',curl_http_status=0,
                   curl_error_class='NOT_STARTED',curl_tls_error_class='NOT_APPLICABLE',curl_output_complete=False,
                   curl_wait_reason='',core_tunnel_ready=None,core_tunnel_ready_count=0,
                   first_core_failure=None,last_core_failure=None,first_cleanup_core_failure=None,
                   cleanup_core_failures=[],cleanup_core_failures_truncated=False,core_failure_count=0,
                   core_pre_cleanup_failure_count=0,core_cleanup_failure_count=0,
                   core_exit_code=None,core_stopped_by_runner=False,core_killed_by_runner=False,
                   first_failure=None,failure_scope='CONFIGURATION',probe_attempts=[],
                   selected_endpoint='',success_endpoint='',request_scheme='',
                   network_budget_seconds=a.timeout,network_duration_ms=0)
        if row['node_id']!=check['node_id']:raise ValueError('Original URI identity mismatch')
        if not check.get('parsed'):return row
        with tempfile.TemporaryDirectory(prefix='vpn-node-') as directory:
            directory=pathlib.Path(directory);ready=directory/'ready.json';cfg=directory/'node.ini';log=directory/'core.log'
            connect_ms=max(1000,int(a.timeout*1000/len(targets)))
            cfg.write_text(f'node_uri={uri}\nlisten_port=0\nready_file={ready}\nconnect_timeout_ms={connect_ms}\n',encoding='utf-8')
            with log.open('wb') as stream:
                process=subprocess.Popen([core,'--config',cfg],stdout=stream,stderr=subprocess.STDOUT)
                try:
                    end=time.monotonic()+10
                    while not ready.exists():
                        if process.poll() is not None:raise StartupFailure('CORE_EXITED_BEFORE_READY')
                        if time.monotonic()>=end:raise StartupFailure('CORE_READY_TIMEOUT')
                        time.sleep(.02)
                    state=json.loads(ready.read_text())
                    if state['pid']!=process.pid or not 0<state['port']<65536:raise ValueError('Core readiness identity mismatch')
                    row['network_test_performed']=True
                    row.update(probe_targets(a,curl,state['port'],directory,targets))
                except StartupFailure as error:row.update(phase='STARTUP_FAILED',reason_code=str(error))
                except subprocess.TimeoutExpired as error:
                    retain_curl(row,None,error.stdout,error.stderr,complete=False)
                    row.update(phase='TIMEOUT',reason_code='TIMEOUT',curl_reason_code='CURL_EXIT_UNAVAILABLE',curl_wait_reason='SUBPROCESS_TIMEOUT')
                except (OSError,ValueError,json.JSONDecodeError):row.update(status='RUNNER_FAILED',phase='RUNNER',reason_code='RUNNER_FAILED',runner_reason_code='RUNNER_FAILED')
                finally:
                    # Snapshot the observation boundary before any owned stop.
                    # Later cleanup cannot replace curl or the first core cause.
                    boundary=log.stat().st_size
                    if process.poll() is None:
                        row['core_stopped_by_runner']=True;process.terminate()
                    try:process.wait(3)
                    except subprocess.TimeoutExpired:
                        row['core_killed_by_runner']=True;process.kill();process.wait()
                    row['core_exit_code']=process.returncode
            retain_core(row,log,boundary)
            return row
    records=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.concurrency) as pool:
        for row in pool.map(test,enumerate(selected)):records.append(row)
    (output/'results.ndjson').write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in records))
    counts=collections.Counter(r['status'] for r in records)
    summary={'schema':'vpn-node-test-v3','source_commit':a.source_commit,'core_sha256':digest(core),'pre_commit':pre['commit'],'pre_manifest_sha256':digest(manifest),'shard':a.shard,'shards':a.shards,'inventory':len(selected),'total_pre_inventory':len(inputs),'selected':len(selected),'finished':len(records),'completed':len(records)==len(selected),'statuses':dict(counts),'runner_failures':counts['RUNNER_FAILED'],'reasons':dict(collections.Counter(r['reason_code'] for r in records)),
             'curl_reasons':dict(collections.Counter(r['curl_reason_code'] for r in records)),
             'network_budget_seconds':a.timeout,'probe_endpoints':[name for name,_ in targets],
             'success_endpoints':dict(collections.Counter(r['success_endpoint'] for r in records if r['status']=='PASS')),
             'probe_curl_reasons':dict(collections.Counter(p['curl_reason_code'] for r in records for p in r['probe_attempts'])),
             'curl_tls_error_classes':dict(collections.Counter(r['curl_tls_error_class'] for r in records if r['curl_exit_code']==35)),
             'curl_35_groups':curl_tls_groups(records),
             'first_core_reasons':dict(collections.Counter(r['first_core_failure']['reason_code'] for r in records if r['first_core_failure'])),
             'cleanup_core_reasons':dict(collections.Counter(r['first_cleanup_core_failure']['reason_code'] for r in records if r['first_cleanup_core_failure'])),
             'failure_scopes':dict(collections.Counter(r['failure_scope'] for r in records)),
             'tunnel_ready':dict(collections.Counter('YES' if r['core_tunnel_ready'] is True else 'NO' if r['core_tunnel_ready'] is False else 'UNKNOWN' for r in records))}
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
    if counts['RUNNER_FAILED']:raise SystemExit(1)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--core',required=True);p.add_argument('--nodes',required=True);p.add_argument('--pre-manifest',required=True);p.add_argument('--output',required=True);p.add_argument('--source-commit',required=True);p.add_argument('--curl',default='curl');p.add_argument('--url',default=None,help='Override the ordered default targets with one HTTPS URL');p.add_argument('--timeout',type=int,default=10,help='Total network budget shared by all verification targets');p.add_argument('--concurrency',type=int,default=8);p.add_argument('--shard',type=int,default=0);p.add_argument('--shards',type=int,default=15);a=p.parse_args()
    if not 1<=a.timeout<=120 or not 1<=a.concurrency<=32 or not 0<=a.shard<a.shards<=20:p.error('Invalid timeout, concurrency or shard')
    run(a)
if __name__=='__main__':main()
