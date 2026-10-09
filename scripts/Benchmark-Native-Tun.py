"""Equivalent controlled TLS load for stable 0.4.11 and candidate proxy/TUN.
Measures data verification, goodput, RTT distribution, process CPU/RSS and ABI
copy counters separately. Linux TUN must run in a disposable network namespace.
"""
import argparse,ctypes as c,hashlib,json,os,pathlib,signal,socket,ssl,statistics,subprocess,sys,tempfile,threading,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests')]
import test_core as core
import test_expanded as peers
from native_tun_peer import NativeTunPeer

def command(*args):return subprocess.run(list(map(str,args)),capture_output=True,text=True,check=True).stdout

def sample(pid):
    if sys.platform=='linux':
        fields=pathlib.Path(f'/proc/{pid}/stat').read_text().split();status=pathlib.Path(f'/proc/{pid}/status').read_text().splitlines()
        values={x.split(':')[0]:int(x.split()[1])*1024 for x in status if x.startswith(('VmRSS:','VmHWM:'))}
        return {'cpu_seconds':(int(fields[13])+int(fields[14]))/os.sysconf('SC_CLK_TCK'),'rss_bytes':values['VmRSS'],'peak_rss_bytes':values['VmHWM']}
    if os.name=='nt':
        from ctypes import wintypes as w
        class Memory(c.Structure):_fields_=[('cb',w.DWORD),('faults',w.DWORD)]+[(name,c.c_size_t) for name in ('peak','rss','paged_peak','paged','nonpaged_peak','nonpaged','pagefile','pagefile_peak')]
        kernel=c.WinDLL('kernel32',use_last_error=True);psapi=c.WinDLL('psapi',use_last_error=True)
        kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];kernel.OpenProcess.restype=w.HANDLE
        kernel.GetProcessTimes.argtypes=[w.HANDLE,c.POINTER(w.FILETIME),c.POINTER(w.FILETIME),c.POINTER(w.FILETIME),c.POINTER(w.FILETIME)]
        psapi.GetProcessMemoryInfo.argtypes=[w.HANDLE,c.POINTER(Memory),w.DWORD];kernel.CloseHandle.argtypes=[w.HANDLE]
        handle=kernel.OpenProcess(0x410,False,pid)
        if not handle:raise c.WinError(c.get_last_error())
        try:
            created,ended,kernel_time,user_time=w.FILETIME(),w.FILETIME(),w.FILETIME(),w.FILETIME();memory=Memory();memory.cb=c.sizeof(memory)
            if not kernel.GetProcessTimes(handle,c.byref(created),c.byref(ended),c.byref(kernel_time),c.byref(user_time)) or not psapi.GetProcessMemoryInfo(handle,c.byref(memory),memory.cb):raise c.WinError(c.get_last_error())
            ticks=lambda t:(int(t.dwHighDateTime)<<32)+int(t.dwLowDateTime)
            return {'cpu_seconds':(ticks(kernel_time)+ticks(user_time))/1e7,'rss_bytes':memory.rss,'peak_rss_bytes':memory.peak}
        finally:kernel.CloseHandle(handle)
    raise RuntimeError('Process measurement backend not supported')

def workload(connect,bytes_count=8*1024*1024):
    rtts=[]
    with connect() as s:
        s.settimeout(30);assert core.exact(s,len(peers.HELLO))==peers.HELLO
        for i in range(100):
            payload=bytes([i])*512;start=time.perf_counter_ns();s.sendall(payload);assert core.exact(s,len(payload))==payload;rtts.append((time.perf_counter_ns()-start)/1e6)
        payload=bytes(range(256))*256;count=bytes_count//len(payload);errors=[];received=hashlib.sha256();expected=hashlib.sha256(payload*count).hexdigest();start=time.monotonic()
        def writer():
            try:
                for _ in range(count):s.sendall(payload)
            except Exception as error:errors.append(str(error))
        task=threading.Thread(target=writer);task.start()
        for _ in range(count):received.update(core.exact(s,len(payload)))
        task.join();duration=time.monotonic()-start
        if errors or received.hexdigest()!=expected:raise RuntimeError('Verified throughput payload mismatch')
    values=sorted(rtts)
    return {'verified_payload_bytes':len(payload)*count,'elapsed_seconds':duration,'goodput_mbit_s':len(payload)*count*8/duration/1e6,'rtt_ms_p50':statistics.median(values),'rtt_ms_p95':values[94],'rtt_ms_p99':values[98]}

def main():
    p=argparse.ArgumentParser();p.add_argument('--stable',type=pathlib.Path,required=True);p.add_argument('--candidate',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--isolated-linux',action='store_true');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    if os.name!='nt' and not a.isolated_linux:p.error('Use a disposable Linux namespace for this equivalent-load benchmark')
    if os.name!='nt':command('ip','link','set','lo','up')
    core.CoreTests.setUpClass();context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key);context.set_alpn_protocols(['h2','http/1.1']);rows=[]
    try:
        # Two transports, three repeated rounds, rotate ordering to expose noise.
        for transport in ('raw','websocket'):
            for repetition in range(3):
                peer=NativeTunPeer('vless',transport=transport,tls_context=context)
                try:
                    labels=[('stable-proxy',a.stable,'proxy'),('candidate-proxy',a.candidate,'proxy'),('candidate-native-tun',a.candidate,'tun')]
                    labels=labels[repetition:]+labels[:repetition]
                    for label,build,mode in labels:
                        with tempfile.TemporaryDirectory() as td:
                            td=pathlib.Path(td);ready=td/'ready.json';cfg=td/'node.ini';log=td/'host.log'
                            cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&type={transport}&sni=localhost&path=/test&fp=chrome\ntls_ca_file={core.CoreTests.ca}\nlisten_port=0\nidle_timeout_ms=60000\nmax_connections=64\n')
                            with log.open('w') as output:
                                process=subprocess.Popen([sys.executable,str(ROOT/'scripts/Native-Tun-Benchmark-Worker.py'),'--build',str(build.resolve()),'--config',str(cfg),'--mode',mode,'--ready',str(ready)],stdin=subprocess.PIPE,text=True,stdout=output,stderr=subprocess.STDOUT)
                                try:
                                    deadline=time.monotonic()+15
                                    while not ready.exists():
                                        if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError(log.read_text())
                                        time.sleep(.01)
                                    info=json.loads(ready.read_text())
                                    if mode=='tun':
                                        if os.name=='nt':command('powershell','-NoProfile','-Command',"$ErrorActionPreference='Stop'; Set-NetIPInterface -InterfaceAlias vpnbbench -AddressFamily IPv4 -NlMtuBytes 1500; New-NetIPAddress -InterfaceAlias vpnbbench -IPAddress 198.18.0.2 -PrefixLength 30 -AddressFamily IPv4 | Out-Null; New-NetRoute -InterfaceAlias vpnbbench -DestinationPrefix 203.0.113.0/24 -NextHop 0.0.0.0 | Out-Null")
                                        else:command('ip','link','set','vpnbbench','up');command('ip','addr','add','198.18.0.2/30','dev','vpnbbench');command('ip','route','add','203.0.113.0/24','dev','vpnbbench')
                                    def connect():
                                        s=socket.create_connection(('203.0.113.9',443) if mode=='tun' else ('127.0.0.1',info['port']),10)
                                        if mode=='proxy':
                                            s.sendall(b'\5\1\0');assert core.exact(s,2)==b'\5\0';s.sendall(b'\5\1\0\1'+socket.inet_aton('203.0.113.9')+b'\1\xbb');assert core.exact(s,10)[1]==0
                                        return s
                                    workload(connect,1024*1024) # equivalent warmup
                                    before=sample(process.pid);result=workload(connect);after=sample(process.pid)
                                    result.update({'label':label,'transport':transport,'repetition':repetition,'cpu_seconds':after['cpu_seconds']-before['cpu_seconds'],'rss_bytes':after['rss_bytes'],'peak_rss_bytes':after['peak_rss_bytes'],'status':'PASS'})
                                    rows.append(result);print(json.dumps(result),flush=True)
                                finally:
                                    process.stdin.write('stop\n');process.stdin.flush()
                                    try:process.wait(15)
                                    except subprocess.TimeoutExpired:process.kill();process.wait();raise RuntimeError('Benchmark stop failed')
                finally:peer.close()
        report={'schema':'vpn-native-tun-performance-v1','status':'PASS','stable_version':'0.4.11','stable_commit':'90a1853114de3e4bcb3deed6747801c10bc5b370','host':'Windows native runner' if os.name=='nt' else 'Linux native namespace','scope':'Same Python C ABI host, same TLS fixture, payloads, warmup and load. Separate controller/peer process is excluded from engine process CPU/RSS. This is a controlled local benchmark, not WAN/physical-device throughput.','measurements':rows}
        (a.output/'performance-report.json').write_text(json.dumps(report,indent=2)+'\n')
    finally:core.CoreTests.tearDownClass()
if __name__=='__main__':main()
