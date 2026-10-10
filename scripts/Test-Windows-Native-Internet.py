"""Bounded real Windows Full TUN acceptance test with owned-policy recovery.

Requires Administrator. Refuses an existing Native process or persistent guard.
Uses original local node URI. Never modifies the installed application or backup.
"""
import argparse, ctypes, hashlib, ipaddress, json, os, pathlib, signal, socket
import ssl, struct, subprocess, tempfile, threading, time, urllib.request, uuid
ROOT = pathlib.Path(__file__).resolve().parents[1]

def powershell(script):
    result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script], capture_output=True, text=True, timeout=15, check=True)
    return result.stdout.strip()

def owns_guard():
    library = ctypes.WinDLL('fwpuclnt.dll')
    library.FwpmEngineOpen0.argtypes = [ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)]
    library.FwpmEngineOpen0.restype = ctypes.c_uint32
    library.FwpmProviderGetByKey0.argtypes = [ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)]
    library.FwpmProviderGetByKey0.restype = ctypes.c_uint32
    library.FwpmEngineClose0.argtypes = [ctypes.c_void_p]
    library.FwpmFreeMemory0.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    engine, provider = ctypes.c_void_p(), ctypes.c_void_p()
    status = library.FwpmEngineOpen0(None,10,None,None,ctypes.byref(engine))
    if status: raise RuntimeError('WFP inspection status '+hex(status))
    try:
        key = ctypes.create_string_buffer(uuid.UUID('56504e01-7617-4e6a-a719-610d394a6b10').bytes_le)
        status = library.FwpmProviderGetByKey0(engine,key,ctypes.byref(provider))
        if status == 0: library.FwpmFreeMemory0(ctypes.byref(provider)); return True
        if status == 0x80320005: return False
        raise RuntimeError('WFP owner inspection status '+hex(status))
    finally: library.FwpmEngineClose0(engine)

def snapshot():
    script = "$r=@(Get-NetRoute -PolicyStore ActiveStore | Where-Object {$_.InterfaceAlias -notlike 'VpnCore*'} | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric | Sort-Object InterfaceIndex,DestinationPrefix,NextHop); $d=@(Get-DnsClientServerAddress | Where-Object {$_.InterfaceAlias -notlike 'VpnCore*'} | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | Sort-Object InterfaceIndex,AddressFamily); [ordered]@{routes=$r;dns=$d} | ConvertTo-Json -Depth 5 -Compress"
    value = json.loads(powershell(script))
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

def query_dns(resolver):
    address = ipaddress.ip_address(resolver)
    query = struct.pack('!HHHHHH',0x5650,0x0100,1,0,0,0)+b'\7example\3com\0'+struct.pack('!HH',1,1)
    with socket.socket(socket.AF_INET if address.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4); sock.sendto(query,(resolver,53)); message, remote = sock.recvfrom(65535)
    if remote[0] != resolver or len(message) < 12: raise ValueError('DNS endpoint or message invalid')
    transaction, flags, _, answers, _, _ = struct.unpack('!HHHHHH',message[:12])
    if transaction != 0x5650 or not flags & 0x8000 or flags & 15 or not answers: raise ValueError('DNS response invalid')
    return {'status':'PASS','answers':answers,'response_bytes':len(message)}

def https(url, marker):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(url,timeout=10) as response:
        data = response.read(2097153)
        if response.status != 200 or not data or len(data)>2097152 or marker not in data: raise ValueError('HTTPS body verification failed')
        return {'status':'PASS','http_status':200,'body_bytes':len(data),'body_sha256':hashlib.sha256(data).hexdigest(),'certificate_verified':True}

def exact(stream,length):
    result=b''
    while len(result)<length:
        data=stream.recv(length-len(result))
        if not data:raise EOFError('DNS TCP response incomplete')
        result+=data
    return result

def query_tcp_dns(resolver):
    destination=ipaddress.ip_address(resolver)
    with socket.socket(socket.AF_INET if destination.version==4 else socket.AF_INET6,socket.SOCK_STREAM) as stream:
        stream.settimeout(10);stream.connect((resolver,53));requests=[]
        for ident,qtype in ((0x5650,1),(0x5651,28)):
            query=struct.pack('!HHHHHH',ident,0x0100,1,0,0,0)+b'\7example\3com\0'+struct.pack('!HH',qtype,1)
            requests.append(struct.pack('!H',len(query))+query)
        stream.sendall(b''.join(requests));sizes=[]
        for ident in (0x5650,0x5651):
            response=exact(stream,struct.unpack('!H',exact(stream,2))[0])
            if len(response)<12 or struct.unpack('!H',response[:2])[0]!=ident or response[3]&15:raise ValueError('DNS TCP response invalid')
            sizes.append(len(response))
        return {'status':'PASS','pipelined_queries':2,'response_bytes':sizes}

def download():
    # A complete, pinned official archive avoids a speed site's geo/bot policy.
    url='https://www.wintun.net/builds/wintun-0.14.1.zip'
    expected='07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(url,timeout=15) as response:
        data=response.read(4194305);digest=hashlib.sha256(data).hexdigest()
        if response.status!=200 or len(data)>4194304 or digest!=expected:raise ValueError('Official download hash mismatch')
        return {'status':'PASS','http_status':200,'body_bytes':len(data),'body_sha256':digest,'certificate_verified':True,'official_sha256_verified':True}


def observe(operation):
    started=time.monotonic()
    try: result=operation()
    except Exception as error: result={'status':'FAIL','error_type':type(error).__name__,'reason':str(error)[:220]}
    result['elapsed_seconds']=round(time.monotonic()-started,3)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=pathlib.Path,required=True)
    parser.add_argument('--nodes',type=pathlib.Path,required=True)
    parser.add_argument('--wintun',type=pathlib.Path,required=True)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    parser.add_argument('--node-index',type=int,default=0)
    parser.add_argument('--legacy-dns',action='store_true')
    parser.add_argument('--crash-recovery',action='store_true')
    args=parser.parse_args(); args.build=args.build.resolve(); args.output=args.output.resolve()
    args.output.mkdir(parents=True,exist_ok=True)
    report={'scope':'Real Windows Full TUN, HTTPS, UDP DNS, graceful disconnect and owned WFP recovery','tests':{}}
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin(): raise RuntimeError('Administrator session required')
        if powershell("@(Get-Process vpn-native-tun,tun2socks -ErrorAction SilentlyContinue).Count")!='0': raise RuntimeError('An existing Native TUN process is active')
        if owns_guard(): raise RuntimeError('An existing persistent Native guard needs explicit recovery; test refused')
        before=snapshot()
        uplink=powershell("$r=@(Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -notlike 'VpnCore*'}); $i=@($r.InterfaceIndex | Select-Object -Unique); if($i.Count -ne 1){throw 'Exactly one IPv4 uplink required'}; $i[0]")
        uri=json.loads(args.nodes.read_text(encoding='utf-8-sig'))[args.node_index]['Uri']
        report['node_id']=hashlib.sha256(uri.encode()).hexdigest()[:16]
        report['source_commit']=json.loads((args.build/'build-provenance.json').read_text())['source_commit']
        launcher=args.build/'vpn-native-tun.exe'
        with tempfile.TemporaryDirectory(prefix='vpn-full-tun-acceptance-') as directory:
            config=pathlib.Path(directory)/'node.ini'; config.write_text('node_uri='+uri+'\nlisten_port=0\nconnect_timeout_ms=10000\nidle_timeout_ms=30000\nmax_connections=64\n',encoding='utf-8')
            log_path=args.output/'native.log'; process=None
            with log_path.open('w',encoding='utf-8') as log:
                process=subprocess.Popen([str(launcher),'--config',str(config),'--wintun',str(args.wintun.resolve()),'--uplink-index',uplink,'--name','VpnCore-Internet-Test'],stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
                def stop():
                    if process.poll() is None:
                        try: process.send_signal(signal.CTRL_BREAK_EVENT)
                        except OSError: pass
                timer=threading.Timer(90,stop); timer.start()
                try:
                    deadline=time.monotonic()+20
                    while 'native_tun_network_ready' not in log_path.read_text(encoding='utf-8',errors='replace'):
                        if process.poll() is not None or time.monotonic()>deadline: raise RuntimeError('Native Full TUN startup did not finish')
                        time.sleep(.05)
                    report['tests']['direct_ipv4_https']=observe(lambda:https('https://1.1.1.1/cdn-cgi/trace',b'ip='))
                    report['tests']['ipv4_udp_dns']=observe(lambda:query_dns('9.9.9.9' if args.legacy_dns else '198.18.0.53'))
                    report['tests']['ipv6_udp_dns']=observe(lambda:query_dns('2620:fe::fe' if args.legacy_dns else 'fd71:5650::53'))
                    report['tests']['system_dns_https']=observe(lambda:https('https://example.com/',b'Example Domain'))
                    report['tests']['ipv4_tcp_dns']=observe(lambda:query_tcp_dns('9.9.9.9' if args.legacy_dns else '198.18.0.53'))
                    report['tests']['ipv6_tcp_dns']=observe(lambda:query_tcp_dns('2620:fe::fe' if args.legacy_dns else 'fd71:5650::53'))
                    report['tests']['official_archive_download']=observe(lambda:download())
                    if args.crash_recovery:
                        process.kill();process.wait(timeout=10)
                        report['guard_survived_crash']=owns_guard()
                finally:
                    stop()
                    try: process.wait(timeout=20)
                    except subprocess.TimeoutExpired: raise RuntimeError('Native remains active after safe stop; no force termination performed')
                    finally: timer.cancel()
                    report['exit_code']=process.returncode
                    if owns_guard():
                        recovered=subprocess.run([str(launcher),'--recover-network'],capture_output=True,text=True,timeout=15)
                        report['owned_recovery_exit_code']=recovered.returncode
                        if recovered.returncode: raise RuntimeError('Owned network recovery failed')
        report['original_routes_dns_restored']=snapshot()==before
        report['owned_wfp_removed']=not owns_guard()
        report['owned_active_routes_after_disconnect']=int(powershell("@(Get-NetRoute -PolicyStore ActiveStore | Where-Object {$_.InterfaceAlias -eq 'VpnCore-Internet-Test'}).Count"))
        report['tests']['internet_after_disconnect']=observe(lambda:https('https://example.com/',b'Example Domain'))
        events=[]
        for line in log_path.read_text(encoding='utf-8',errors='replace').splitlines():
            try: event=json.loads(line)
            except ValueError: continue
            if event.get('event') in ('tun_flow_failure','native_tun_network_ready'): events.append(event)
        report['events']=events
        report['status']='PASS' if report['original_routes_dns_restored'] and report['owned_wfp_removed'] and report['owned_active_routes_after_disconnect']==0 and (report['guard_survived_crash'] if args.crash_recovery else report['exit_code']==0) and all(test['status']=='PASS' for test in report['tests'].values()) else 'FAIL'
    except BaseException as error:
        report['status']='FAIL'; report['error_type']=type(error).__name__; report['reason']=str(error)[:240]
    finally:
        (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report),flush=True)
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__': raise SystemExit(main())
