"""TLS node over a real IPv6 veth uplink with a fresh neighbor cache + strict policy."""
import argparse,errno,importlib.util,json,os,pathlib,socket,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'sdk/native'),str(ROOT/'sdk/linux')]
import test_core as core
import test_expanded as peers
from tun_host import TunHost
from native_tun import LinuxPolicy,MARK,TABLE
spec=importlib.util.spec_from_file_location('device',ROOT/'scripts/Test-Native-Tun-Device.py');device=importlib.util.module_from_spec(spec);spec.loader.exec_module(device)
def cmd(*args):return subprocess.run(list(map(str,args)),capture_output=True,text=True,check=True).stdout
def main():
    p=argparse.ArgumentParser();p.add_argument('--build',required=True,type=pathlib.Path);p.add_argument('--output',required=True,type=pathlib.Path);p.add_argument('--isolated-linux',action='store_true');a=p.parse_args()
    if not a.isolated_linux or os.geteuid()!=0:p.error('Disposable root network namespace required')
    a.build=a.build.resolve();a.output.mkdir(parents=True,exist_ok=True);remote='vpncorepeer6';server=None;rows=[]
    core.CoreTests.setUpClass()
    try:
        cmd('ip','netns','add',remote);cmd('ip','link','add','vpnup6','type','veth','peer','name','vpnpeer6')
        cmd('ip','link','set','vpnpeer6','netns',remote);cmd('ip','link','set','vpnup6','up')
        cmd('ip','-6','addr','add','2001:db8:face::1/64','dev','vpnup6','nodad')
        for args in [('ip','link','set','lo','up'),('ip','link','set','vpnpeer6','up'),('ip','-6','addr','add','2001:db8:face::2/64','dev','vpnpeer6','nodad')]:cmd('ip','netns','exec',remote,*args)
        for transport in ('raw','websocket'):
            with tempfile.TemporaryDirectory() as td:
                td=pathlib.Path(td);ready=td/'peer.json';server_src=td/'peer.py'
                server_src.write_text("import sys,ssl,json,pathlib\nsys.path.insert(0,"+repr(str(ROOT/'tests'))+")\nfrom native_tun_peer import NativeTunPeer\ncontext=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\ncontext.load_cert_chain("+repr(str(core.CoreTests.cert))+","+repr(str(core.CoreTests.key))+")\np=NativeTunPeer('vless',transport="+repr(transport)+",tls_context=context,bind_address='2001:db8:face::2')\npathlib.Path("+repr(str(ready))+").write_text(json.dumps({'port':p.port}))\ninput()\np.close()\nassert p.errors==[],p.errors\n")
                server=subprocess.Popen(['ip','netns','exec',remote,sys.executable,str(server_src)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                deadline=time.monotonic()+10
                while not ready.exists():
                    if server.poll() is not None or time.monotonic()>deadline:raise RuntimeError('IPv6 controlled peer startup failed')
                    time.sleep(.01)
                port=json.loads(ready.read_text())['port'];cfg=td/'node.ini'
                cfg.write_text(f'node_uri=vless://{peers.ID}@[2001:db8:face::2]:{port}?security=tls&type={transport}&sni=localhost&fp=chrome&path=/test\ntls_ca_file={core.CoreTests.ca}\n')
                def protect(fd):
                    with socket.socket(fileno=os.dup(fd)) as s:s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'vpnup6\0');s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,MARK)
                    return True
                host=TunHost(a.build,cfg,name='vpnv6tun',protect=protect,resolve=lambda _:['2001:db8:face::2'])
                policy=LinuxPolicy('vpnv6tun',['2001:db8:face::2'],port)
                try:
                    host.start();policy.acquire()
                    cmd('ip','link','set','vpnv6tun','up');cmd('ip','addr','add','198.18.0.2/30','dev','vpnv6tun')
                    cmd('ip','-6','addr','add','fd71:5650::2/126','dev','vpnv6tun','nodad')
                    cmd('ip','route','add','203.0.113.0/24','dev','vpnv6tun');cmd('ip','-6','route','add','2001:db8::/32','dev','vpnv6tun')
                    cmd('ip','-6','neigh','flush','dev','vpnup6')
                    for row in device.transfers():row.update({'node_uplink':'IPv6 veth with fresh ND','transport':transport,'security':'tls'});rows.append(row)
                    assert host.protected>=4,'Node sockets were not protected'
                    neighbors=json.loads(cmd('ip','-j','-6','neigh','show','dev','vpnup6'))
                    assert any(x['dst']=='2001:db8:face::2' and x.get('lladdr') for x in neighbors),neighbors
                    with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as s:
                        s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'vpnup6\0')
                        try:s.sendto(b'forbidden physical DNS',('2001:db8:face::2',53));raise AssertionError('IPv6 DNS bypass')
                        except OSError as e:assert e.errno==errno.EPERM,repr(e)
                    rows.append({'test':'PHYSICAL_IPV6_NODE_ND_ALLOWED_DNS_BLOCKED','transport':transport,'status':'PASS'})
                finally:assert host.stop()==0;policy.close()
                server.stdin.write('\n');server.stdin.flush();out,err=server.communicate(timeout=10)
                if server.returncode:raise RuntimeError('IPv6 independent peer failed: '+err)
                server=None
        report={'status':'PASS','scope':'Actual independent TLS node across a physical veth/namespace IPv6 uplink. Fresh neighbor discovery succeeds; unmarked physical UDP DNS remains blocked. TCP/UDP destinations use both IP families.','tests':rows}
        (a.output/'ipv6-uplink-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:
        if server and server.poll() is None:server.kill();server.wait(10)
        subprocess.run(['ip','link','del','vpnup6'],capture_output=True)
        subprocess.run(['ip','netns','delete',remote],capture_output=True);core.CoreTests.tearDownClass()
if __name__=='__main__':main()
