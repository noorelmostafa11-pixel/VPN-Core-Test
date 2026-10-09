"""Equivalent TLS workload inside the same Android app process for three paths.
Client Java CPU is included for all paths. Peer CPU runs on the host and is
excluded. Emulator measurements are not physical-device/WAN performance.
"""
import argparse,json,os,pathlib,ssl,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'))
import test_core as core
import test_expanded as peers
from native_tun_peer import NativeTunPeer
PACKAGE='com.noorelmostafa.vpnexperiment'
def call(*args):return subprocess.run(list(map(str,args)),capture_output=True,text=True,check=True).stdout
def main():
    p=argparse.ArgumentParser();p.add_argument('--stable',required=True,type=pathlib.Path);p.add_argument('--candidate',required=True,type=pathlib.Path);p.add_argument('--output',required=True,type=pathlib.Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    core.CoreTests.setUpClass();rows=[]
    try:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key);context.set_alpn_protocols(['h2','http/1.1'])
        with tempfile.TemporaryDirectory() as td:
            own_signing=not os.environ.get('VPN_CORE_EXPERIMENT_KEYSTORE')
            if own_signing:
                os.environ['VPN_CORE_EXPERIMENT_KEYSTORE']=str(pathlib.Path(td)/'benchmark-key.p12')
                subprocess.run(['adb','uninstall',PACKAGE],capture_output=True)
            assets=pathlib.Path(td);(assets/'ca.pem').write_bytes(core.CoreTests.ca.read_bytes());(assets/'node.ini').write_text(f'node_uri=vless://{peers.ID}@10.0.2.2:@PORT@?security=tls&type=@TRANSPORT@&sni=localhost&path=/test&fp=chrome\ntls_ca_file=@CA@\nlisten_port=0\nidle_timeout_ms=60000\nmax_connections=64\n')
            apks={}
            for label,build in (('stable',a.stable),('candidate',a.candidate)):
                apk=pathlib.Path(td).parent/(pathlib.Path(td).name+'-'+label+'.apk')
                call(sys.executable,ROOT/'scripts/Build-Android-Experiment.py','--build',build,'--fixture-assets',assets,'--output',apk);apks[label]=apk
            installed=None
            try:
                for transport in ('raw','websocket'):
                    for repetition in range(3):
                        labels=[('stable-proxy','stable',True),('candidate-proxy','candidate',True),('candidate-native-tun','candidate',False)];labels=labels[repetition:]+labels[:repetition]
                        peer=NativeTunPeer('vless',transport=transport,tls_context=context)
                        try:
                            for label,build,proxy in labels:
                                call('adb','shell','am','force-stop',PACKAGE)
                                if installed!=build:
                                    call('adb','install','-r',apks[build]);call('adb','shell','cmd','appops','set',PACKAGE,'ACTIVATE_VPN','allow');call('adb','shell','pm','grant',PACKAGE,'android.permission.POST_NOTIFICATIONS');installed=build
                                application_uid=int(call('adb','shell','run-as',PACKAGE,'id','-u').strip())
                                call('adb','shell','run-as',PACKAGE,'rm','-f','files/benchmark-report.json','files/fixture-report.txt')
                                call('adb','shell','am','start','-n',PACKAGE+'/.MainActivity','--ez','fixture','true','--ez','benchmark','true','--ez','proxy',str(proxy).lower(),'--ei','peer_port',str(peer.port),'--es','transport',transport)
                                deadline=time.monotonic()+120;result=None
                                while time.monotonic()<deadline:
                                    status=subprocess.run(['adb','shell','run-as',PACKAGE,'cat','files/fixture-report.txt'],capture_output=True,text=True)
                                    if status.returncode==0:
                                        if not status.stdout.startswith('PASS:'):
                                            (a.output/'failure-connectivity.txt').write_text(call('adb','shell','dumpsys','connectivity'))
                                            (a.output/'failure-network-policy.txt').write_text(call('adb','shell','dumpsys','netpolicy'))
                                            raise RuntimeError(status.stdout+call('adb','logcat','-d','-s','AndroidRuntime','VpnTunFixture','VpnCoreService'))
                                        result=json.loads(call('adb','shell','run-as',PACKAGE,'cat','files/benchmark-report.json'));break
                                    time.sleep(.2)
                                if result is None:raise RuntimeError('Android benchmark deadline exceeded')
                                result.update(label=label,transport=transport,repetition=repetition,application_uid=application_uid);rows.append(result);print(json.dumps(result),flush=True)
                            if peer.errors:raise RuntimeError(str(peer.errors))
                        finally:call('adb','shell','am','force-stop',PACKAGE);peer.close()
            finally:
                for apk in apks.values():apk.unlink(missing_ok=True)
                if own_signing:os.environ.pop('VPN_CORE_EXPERIMENT_KEYSTORE',None)
        if len({r['application_uid'] for r in rows})!=1:raise RuntimeError('Performance paths changed application UID')
        report={'schema':'vpn-native-tun-performance-v1','status':'PASS','stable_version':'0.4.11','stable_commit':'90a1853114de3e4bcb3deed6747801c10bc5b370','host':'Android API 35 x86_64 emulator','scope':__doc__,'measurements':rows}
        (a.output/'performance-report.json').write_text(json.dumps(report,indent=2)+'\n')
    finally:core.CoreTests.tearDownClass()
if __name__=='__main__':main()
