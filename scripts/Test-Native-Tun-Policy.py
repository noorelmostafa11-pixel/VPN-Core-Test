"""Owned kill-switch and rollback tests on isolated Linux / disposable Windows.
Full physical traffic is briefly blocked. No global firewall reset is performed.
"""
import argparse,json,os,pathlib,signal,socket,ssl,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'sdk/native'),str(ROOT/'sdk/linux'),str(ROOT/'scripts')]
from native_tun_peer import NativeTunPeer
from tun_host import TunHost
import test_core as core
import test_expanded as peers
from importlib.util import spec_from_file_location,module_from_spec
spec=spec_from_file_location('device',ROOT/'scripts/Test-Native-Tun-Device.py');device=module_from_spec(spec);spec.loader.exec_module(device)

def cmd(*args):return subprocess.run(list(map(str,args)),capture_output=True,text=True,check=True).stdout

def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--isolated-linux',action='store_true');a=p.parse_args();a.build=a.build.resolve();a.output.mkdir(parents=True,exist_ok=True)
    if os.name!='nt' and not a.isolated_linux:p.error('Use a disposable Linux network namespace')
    core.CoreTests.setUpClass();context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key);peer=NativeTunPeer('vless',tls_context=context);rows=[]
    try:
        with tempfile.TemporaryDirectory() as td:
            cfg=pathlib.Path(td)/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&sni=localhost&fp=chrome\ntls_ca_file={core.CoreTests.ca}\n')
            if os.name=='nt':
                physical=cmd('powershell','-NoProfile','-Command',"(Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.ConnectionState -eq 'Connected' -and $_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1).InterfaceIndex").strip()
                uplink=cmd('powershell','-NoProfile','-Command',"(Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -like '*Loopback*'} | Select-Object -First 1).InterfaceIndex").strip()
                logfile=a.output/'windows-policy.log'
                with logfile.open('w') as log:
                    process=subprocess.Popen([str(a.build/'vpn-native-tun.exe'),'--config',str(cfg),'--wintun',str(a.build/'wintun.dll'),'--uplink-index',uplink,'--name','VpnCore-Policy-CI','--test-policy'],stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
                    try:
                        deadline=time.monotonic()+20
                        while 'native_tun_network_ready' not in logfile.read_text():
                            if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError(logfile.read_text())
                            time.sleep(.05)
                        rows+=device.transfers()
                        # Physical TCP SYN is rejected by WFP, not a remote timeout.
                        with socket.socket() as s:
                            s.settimeout(2);s.setsockopt(socket.IPPROTO_IP,31,socket.htonl(int(physical)))
                            try:s.connect(('1.1.1.1',443));raise AssertionError('Physical IPv4 escaped kill switch')
                            except OSError as e:assert e.winerror==10013,repr(e)
                        rows.append({'test':'WFP_PHYSICAL_IPV4_BLOCK','status':'PASS'})
                        dns=cmd('powershell','-NoProfile','-Command',"Get-DnsClientServerAddress -InterfaceAlias VpnCore-Policy-CI | ConvertTo-Json -Depth 4")
                        assert '9.9.9.9' in dns and '2620:fe::fe' in dns
                        rows.append({'test':'OWNED_ADAPTER_DNS_IPV4_IPV6','status':'PASS'})
                    finally:
                        if process.poll() is None:process.send_signal(signal.CTRL_BREAK_EVENT)
                        try:process.wait(15)
                        except subprocess.TimeoutExpired:process.kill();process.wait()
                        # Explicit recovery also covers the intentional crash case.
                        cmd(a.build/'vpn-native-tun.exe','--recover-network')
            else:
                from native_tun import LinuxPolicy,MARK,TABLE
                cmd('ip','link','set','lo','up')
                host=TunHost(a.build,cfg,name='vpncorepolicy',protect=lambda _:True,resolve=lambda _:['127.0.0.1'])
                policy=LinuxPolicy('vpncorepolicy',['127.0.0.1'],peer.port)
                try:
                    host.start();policy.acquire()
                    cmd('ip','link','set','vpncorepolicy','up');cmd('ip','addr','add','198.18.0.2/30','dev','vpncorepolicy');cmd('ip','-6','addr','add','fd71:5650::2/126','dev','vpncorepolicy','nodad')
                    cmd('ip','route','add','203.0.113.0/24','dev','vpncorepolicy');cmd('ip','-6','route','add','2001:db8::/32','dev','vpncorepolicy');rows+=device.transfers()
                    cmd('ip','link','add','vpnphys','type','dummy');cmd('ip','link','set','vpnphys','up');cmd('ip','addr','add','192.0.2.2/24','dev','vpnphys');cmd('ip','-6','addr','add','2001:db8:ffff::2/64','dev','vpnphys','nodad')
                    for family,dest in ((socket.AF_INET,'192.0.2.9'),(socket.AF_INET6,'2001:db8:ffff::9')):
                        with socket.socket(family,socket.SOCK_DGRAM) as s:s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'vpnphys\0');s.sendto(b'forbidden DNS egress',(dest,53))
                    state=json.loads(cmd('nft','-j','list','table','inet',TABLE));drops=sum(v['counter'].get('packets',0) for item in state['nftables'] for v in item.get('rule',{}).get('expr',[]) if 'counter' in v)
                    assert drops>=2,state;rows.append({'test':'NFT_PHYSICAL_DNS_IPV4_IPV6_BLOCK','status':'PASS','blocked_packets':drops})
                    assert host.stop()==0
                    assert subprocess.run(['nft','list','table','inet',TABLE],capture_output=True).returncode==0
                    rows.append({'test':'GUARD_REMAINS_WHEN_TUN_STOPS','status':'PASS'})
                    policy.close();assert subprocess.run(['nft','list','table','inet',TABLE],capture_output=True).returncode!=0
                finally:host.stop();policy.close()
            assert peer.errors==[],peer.errors
            rows.append({'test':'OWNED_POLICY_RECOVERY','status':'PASS'})
        report={'status':'PASS','platform':sys.platform,'tests':rows};(a.output/'policy-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:peer.close();core.CoreTests.tearDownClass()
if __name__=='__main__':main()
