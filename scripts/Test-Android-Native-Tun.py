"""Run real Android VpnService/JNI TCP/UDP in an emulator with TLS peers."""
import argparse,json,pathlib,ssl,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'))
import test_core as core
import test_expanded as peers
from native_tun_peer import NativeTunPeer
PACKAGE='com.noorelmostafa.vpnexperiment'
def call(*args):return subprocess.run(list(map(str,args)),capture_output=True,text=True,check=True).stdout

def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    core.CoreTests.setUpClass();rows=[]
    try:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key);context.set_alpn_protocols(['h2','http/1.1'])
        with tempfile.TemporaryDirectory() as td:
            assets=pathlib.Path(td);(assets/'ca.pem').write_bytes(core.CoreTests.ca.read_bytes())
            (assets/'node.ini').write_text(f'node_uri=vless://{peers.ID}@10.0.2.2:@PORT@?security=tls&type=@TRANSPORT@&sni=localhost&path=/test&fp=chrome\ntls_ca_file=@CA@\nmax_connections=64\n')
            apk=a.output/'vpn-core-fixture.apk'
            call(sys.executable,ROOT/'scripts/Build-Android-Experiment.py','--build',a.build,'--fixture-assets',assets,'--output',apk)
            call('adb','install','-r',apk);call('adb','shell','cmd','appops','set',PACKAGE,'ACTIVATE_VPN','allow')
            call('adb','shell','pm','grant',PACKAGE,'android.permission.POST_NOTIFICATIONS')
            for transport in ('raw','websocket'):
                peer=NativeTunPeer('vless',transport=transport,tls_context=context)
                try:
                    call('adb','shell','am','force-stop',PACKAGE)
                    subprocess.run(['adb','shell','run-as',PACKAGE,'rm','-f','files/fixture-report.txt'],capture_output=True)
                    call('adb','shell','am','start','-n',PACKAGE+'/.MainActivity','--ez','fixture','true','--ei','peer_port',str(peer.port),'--es','transport',transport)
                    deadline=time.monotonic()+60;report=''
                    while time.monotonic()<deadline:
                        result=subprocess.run(['adb','shell','run-as',PACKAGE,'cat','files/fixture-report.txt'],capture_output=True,text=True)
                        if result.returncode==0:report=result.stdout.strip();break
                        time.sleep(.5)
                    (a.output/(transport+'-device.log')).write_text(call('adb','logcat','-d','-s','VpnCoreService','VpnTunFixture','AndroidRuntime'))
                    if not report.startswith('PASS:'):raise RuntimeError('Actual Android TUN failed: '+report)
                    if peer.errors:raise RuntimeError('Independent TLS peer errors: '+str(peer.errors))
                    rows.append({'test':'ANDROID_VPNSERVICE_JNI_FD_TCP_UDP_IPV4_IPV6','transport':transport,'security':'tls','status':'PASS'})
                finally:peer.close();call('adb','shell','am','force-stop',PACKAGE)
        (a.output/'android-device-report.json').write_text(json.dumps({'status':'PASS','runtime':'Android API 35 x86_64 emulator','tests':rows},indent=2)+'\n');print(json.dumps(rows))
    finally:core.CoreTests.tearDownClass()
if __name__=='__main__':main()
