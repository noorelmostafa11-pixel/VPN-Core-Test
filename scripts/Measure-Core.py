"""Measure first actual TCP transfer, UDP round trips and Linux process resources.
Synthetic local peers only. Optional baseline runs under the same conditions.
"""
import argparse,contextlib,hashlib,json,os,pathlib,socket,statistics,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'))
import test_core as core
import test_expanded as old
import test_udp_sdk as sdk

def percentile(values,p):return sorted(values)[min(len(values)-1,int((len(values)-1)*p))]
def resources(pid):
    root=pathlib.Path('/proc')/str(pid)
    if os.name!='posix' or not pathlib.Path('/proc/self/ns/pid').exists():return {'status':'NOT_VERIFIED','reason':'Linux /proc metrics required'}
    namespace=os.readlink('/proc/self/ns/pid')
    def matches(path):
        try:
            if os.readlink(path/'ns/pid')!=namespace:return False
            lines=(path/'status').read_text().splitlines()
            ids=next(line.split()[1:] for line in lines if line.startswith('NSpid:'))
            return int(ids[-1])==pid
        except (OSError,StopIteration,ValueError):return False
    # A container may expose a host /proc mount while getpid/Popen uses namespace
    # PIDs. Resolve only within our own PID namespace, never an unrelated process.
    if not matches(root):root=next((path for path in pathlib.Path('/proc').iterdir() if path.name.isdigit() and matches(path)),None)
    if root is None:return {'status':'NOT_VERIFIED','reason':'Child process not visible in the available /proc mount'}
    status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in (root/'status').read_text().splitlines() if ':' in line}
    stat=(root/'stat').read_text().split()
    return {'rss_kb':int(status['VmRSS'].split()[0]),'threads':int(status['Threads']),'fds':len(list((root/'fd').iterdir())),'cpu_seconds':(int(stat[13])+int(stat[14]))/os.sysconf('SC_CLK_TCK')}
def measure(binary,cycles):
    binary=pathlib.Path(binary).resolve();peer=old.Peer('vless');samples=[];stop_times=[];udp_times=[];eof_timeouts=0
    udp_peer=sdk.ShadowsocksUdpPeer('aes-128-gcm')
    try:
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td);ready=td/'ready.json';config=td/'node.ini'
            config.write_text(f'node_uri=vless://{old.ID}@127.0.0.1:{peer.port}?security=none&type=raw\nlisten_port=0\nready_file={ready}\nconnect_timeout_ms=1000\n')
            with (td/'run.log').open('wb') as log:
                process=subprocess.Popen([binary,'--config',config],stdout=log,stderr=subprocess.STDOUT)
                try:
                    end=time.monotonic()+5
                    while not ready.exists():
                        if process.poll() is not None or time.monotonic()>end:raise RuntimeError('Core readiness failed')
                        time.sleep(.005)
                    port=json.loads(ready.read_text())['port'];snapshots=[resources(process.pid)]
                    for i in range(cycles+1):
                        start=time.monotonic()
                        with socket.create_connection(('127.0.0.1',port),2) as client:
                            client.settimeout(2);client.sendall(b'\5\1\0');assert core.exact(client,2)==b'\5\0'
                            client.sendall(b'\5\1\0\1\x7f\0\0\1\0\x50');assert core.exact(client,10)[1]==0
                            assert core.exact(client,len(old.HELLO))==old.HELLO
                            payload=b'measured first transfer';client.sendall(payload);assert core.exact(client,len(payload))==payload
                            elapsed=(time.monotonic()-start)*1000
                            if i:samples.append(elapsed)
                            # Verify the peer/core close path before counting the
                            # session as retired; close() alone can leave traffic
                            # queued in an intermediate socket proxy.
                            client.shutdown(socket.SHUT_WR);client.settimeout(.25)
                            try:
                                if client.recv(1)!=b'':raise RuntimeError('Unexpected data after measured exchange')
                            except socket.timeout:eof_timeouts+=1
                        time.sleep(.06);snapshots.append(resources(process.pid))
                    start=time.monotonic();process.terminate()
                    while process.poll() is None:
                        if time.monotonic()-start>3:raise RuntimeError('Stop deadline exceeded')
                        time.sleep(.001)
                    stop_times.append((time.monotonic()-start)*1000)
                finally:
                    if process.poll() is None:process.kill();process.wait()
            import base64
            secret=base64.urlsafe_b64encode(('aes-128-gcm:'+udp_peer.password).encode()).decode()
            ready.unlink();config.write_text(f'node_uri=ss://{secret}@127.0.0.1:{udp_peer.port}\nlisten_port=0\nready_file={ready}\nconnect_timeout_ms=1000\n')
            with (td/'udp.log').open('wb') as log:
                process=subprocess.Popen([binary,'--config',config],stdout=log,stderr=subprocess.STDOUT)
                try:
                    end=time.monotonic()+5
                    while not ready.exists():
                        if process.poll() is not None or time.monotonic()>end:raise RuntimeError('Core UDP readiness failed')
                        time.sleep(.005)
                    port=json.loads(ready.read_text())['port']
                    with socket.create_connection(('127.0.0.1',port),2) as control,socket.socket(type=socket.SOCK_DGRAM) as client:
                        control.settimeout(2);client.settimeout(2);control.sendall(b'\5\1\0');assert core.exact(control,2)==b'\5\0';control.sendall(b'\5\3\0\1'+bytes(6));reply=core.exact(control,10);assert reply[1]==0
                        relay=('127.0.0.1',int.from_bytes(reply[-2:],'big'));packet=b'\0\0\0\1\x7f\0\0\1\0\x35measured UDP'
                        for _ in range(cycles):
                            start=time.monotonic();client.sendto(packet,relay);assert client.recvfrom(4096)[0]==packet;udp_times.append((time.monotonic()-start)*1000)
                finally:process.terminate();process.wait(3)
        return {'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'cycles':cycles,'tcp_first_transfer_ms':{'p50':statistics.median(samples),'p95':percentile(samples,.95)},'udp_roundtrip_ms':{'p50':statistics.median(udp_times),'p95':percentile(udp_times,.95)},'stop_ms':stop_times,'eof_wait_ms':250,'eof_timeouts':eof_timeouts,'resources':snapshots,'scope':'Local synthetic raw VLESS TCP / AES-128-GCM SS UDP; not device/VPN-route or internet performance'}
    finally:peer.close();udp_peer.close()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--core',required=True);p.add_argument('--baseline');p.add_argument('--cycles',type=int,default=30);p.add_argument('--output',required=True);a=p.parse_args()
    if a.cycles<5:p.error('Use at least five cycles')
    report={'candidate':measure(a.core,a.cycles),'baseline':measure(a.baseline,a.cycles) if a.baseline else 'NOT_VERIFIED'}
    pathlib.Path(a.output).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v if isinstance(v,str) else {q:v[q] for q in ('tcp_first_transfer_ms','udp_roundtrip_ms','stop_ms')} for k,v in report.items()}))
if __name__=='__main__':main()
