"""Actual OS TUN TCP/UDP IPv4/IPv6 encrypted transfer and lifecycle tests.
Linux must run inside a disposable network namespace; Windows uses signed Wintun.
"""
import argparse,json,os,pathlib,signal,socket,ssl,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'sdk/native'),str(ROOT/'sdk/linux')]
import test_core as core
import test_expanded as peers
from native_tun_peer import NativeTunPeer
from tun_host import TunHost

def command(*args):return subprocess.run(list(args),check=True,capture_output=True,text=True).stdout

def transfers():
    rows=[]
    for address in ('203.0.113.9','2001:db8::9'):
        family=socket.AF_INET6 if ':' in address else socket.AF_INET
        start=time.monotonic()
        with socket.socket(family,socket.SOCK_STREAM) as s:
            s.settimeout(8);s.connect((address,443));assert core.exact(s,len(peers.HELLO))==peers.HELLO
            for payload in (b'first encrypted packet',bytes(range(256))*256):s.sendall(payload);assert core.exact(s,len(payload))==payload
        rows.append({'test':'OS_TUN_TCP_IPV6' if family==socket.AF_INET6 else 'OS_TUN_TCP_IPV4','status':'PASS','elapsed_seconds':time.monotonic()-start})
        with socket.socket(family,socket.SOCK_DGRAM) as s:
            s.settimeout(8)
            sizes=(0,1,512,1200,32768,65527 if family==socket.AF_INET6 else 65507)
            for size in sizes:
                payload=bytes([size%256])*size;s.sendto(payload,(address,443));reply,source=s.recvfrom(65535);assert reply==payload and source[1]==443
        rows.append({'test':'OS_TUN_UDP_IPV6' if family==socket.AF_INET6 else 'OS_TUN_UDP_IPV4','status':'PASS','verified_datagram_sizes':list(sizes),'fragmented_roundtrip':True})
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--isolated-linux',action='store_true');a=p.parse_args();a.build=a.build.resolve();a.output.mkdir(parents=True,exist_ok=True)
    if os.name!='nt' and not a.isolated_linux:p.error('Linux test requires --isolated-linux in a disposable namespace')
    if os.name!='nt':command('ip','link','set','lo','up')
    core.CoreTests.setUpClass();context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key);context.set_alpn_protocols(['h2','http/1.1'])
    results=[]
    try:
        for transport in ('raw','websocket'):
            peer=NativeTunPeer('vless',transport=transport,tls_context=context)
            with tempfile.TemporaryDirectory() as td:
                cfg=pathlib.Path(td)/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&type={transport}&sni=localhost&path=/test&fp=chrome\ntls_ca_file={core.CoreTests.ca}\nmax_connections=64\n')
                host=None;process=None;policy=None;log=None
                try:
                    if os.name=='nt':
                        uplink=command('powershell','-NoProfile','-Command',"(Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -like '*Loopback*'} | Select-Object -First 1).InterfaceIndex").strip()
                        log=open(a.output/('windows-'+transport+'.log'),'w')
                        process=subprocess.Popen([str(a.build/'vpn-native-tun.exe'),'--config',str(cfg),'--wintun',str(a.build/'wintun.dll'),'--uplink-index',uplink,'--name','VpnCore-CI','--test-routes'],stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
                        deadline=time.monotonic()+20
                        while 'native_tun_network_ready' not in (a.output/('windows-'+transport+'.log')).read_text():
                            if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Wintun startup: '+(a.output/('windows-'+transport+'.log')).read_text())
                            time.sleep(.05)
                    else:
                        host=TunHost(a.build,cfg,name='vpncoreci',protect=lambda _:True,resolve=lambda _:['127.0.0.1']);host.start()
                        command('ip','link','set','vpncoreci','up');command('ip','addr','add','198.18.0.2/30','dev','vpncoreci');command('ip','-6','addr','add','fd71:5650::2/126','dev','vpncoreci','nodad')
                        command('ip','route','add','203.0.113.0/24','dev','vpncoreci');command('ip','-6','route','add','2001:db8::/32','dev','vpncoreci')
                    for row in transfers():row['transport']=transport;row['security']='tls';results.append(row)
                    assert peer.errors==[],peer.errors
                finally:
                    if host:assert host.stop()==0
                    if process:
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                        try:process.wait(15)
                        except subprocess.TimeoutExpired:process.kill();process.wait();raise RuntimeError('Windows graceful disconnect timeout')
                        assert process.returncode==0,'Windows disconnect failed'
                    if log:log.close()
                    peer.close()
                results.append({'test':'OS_TUN_DISCONNECT_AND_JOIN','transport':transport,'status':'PASS'})
                if os.name!='nt':assert subprocess.run(['ip','link','show','vpncoreci'],capture_output=True).returncode!=0
        report={'schema':'vpn-native-tun-device-v1','status':'PASS','host':sys.platform,'tests':results,'scope':'Actual OS Wintun or /dev/net/tun with TLS raw and WebSocket; numeric controlled destinations. Security policy is tested separately.'}
        (a.output/'device-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:core.CoreTests.tearDownClass()
if __name__=='__main__':main()
