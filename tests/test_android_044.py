"""Same independent TLS/protocol peers through the source-built Android core."""
import contextlib,json,os,pathlib,subprocess,tempfile,time,unittest
from urllib.parse import urlsplit
from test_portable_044 import PortableTransportTests

def adb(*args, **kwargs):
    return subprocess.run(['adb',*[str(a) for a in args]],check=True,**kwargs)

class AndroidTransportTests(PortableTransportTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.device='/data/local/tmp/vpn-core-ci'
        adb('shell','mkdir','-p',cls.device)
        source=pathlib.Path(os.environ['VPN_CORE_ANDROID_BUILD'])
        for name in ['vpn-core','libvpn-core.so','libvpn-tls.so','core-api-smoke']:
            adb('push',source/name,cls.device+'/'+name,stdout=subprocess.DEVNULL)
        adb('shell','chmod','700',cls.device+'/vpn-core',cls.device+'/core-api-smoke')
        adb('push',cls.ca,cls.device+'/ca.pem',stdout=subprocess.DEVNULL)
        adb('shell',cls.device+'/vpn-core','--self-test')
        adb('shell',cls.device+'/vpn-core','--check-components')
        adb('shell',cls.device+'/core-api-smoke',cls.device+'/libvpn-core.so')

    @contextlib.contextmanager
    def core(self,uri):
        with tempfile.TemporaryDirectory(dir=self.directory) as td, contextlib.ExitStack() as cleanup:
            td=pathlib.Path(td);config=td/'node.ini';log_path=td/'core.log'
            device_ready=self.device+'/ready.json'
            # Bridge only the synthetic peer endpoint; avoid emulator NAT readiness.
            peer_port=urlsplit(uri).port
            if urlsplit(uri).hostname!='127.0.0.1' or peer_port is None:
                raise ValueError('Android fixture requires a local synthetic peer')
            reverse=int(subprocess.check_output(['adb','reverse','tcp:0','tcp:'+str(peer_port)],text=True).strip())
            cleanup.callback(adb,'reverse','--remove','tcp:'+str(reverse))
            uri=uri.replace('@127.0.0.1:'+str(peer_port)+'?', '@127.0.0.1:'+str(reverse)+'?',1)
            config.write_text(f'node_uri={uri}\nlisten_port=0\nready_file={device_ready}\nconnect_timeout_ms=5000\nidle_timeout_ms=15000\ntls_ca_file={self.device}/ca.pem\n')
            adb('shell','rm','-f',device_ready)
            adb('push',config,self.device+'/node.ini',stdout=subprocess.DEVNULL)
            forward=None;pid=None
            with log_path.open('w') as log:
                process=subprocess.Popen(['adb','shell',self.device+'/vpn-core','--config',self.device+'/node.ini'],stdout=log,stderr=subprocess.STDOUT)
                try:
                    end=time.monotonic()+15
                    while True:
                        r=subprocess.run(['adb','shell','cat',device_ready],capture_output=True,text=True)
                        if r.returncode==0:
                            state=json.loads(r.stdout);break
                        if process.poll() is not None or time.monotonic()>end:raise AssertionError(log_path.read_text())
                        time.sleep(.1)
                    pid=int(state['pid'])
                    forward=int(subprocess.check_output(['adb','forward','tcp:0','tcp:'+str(state['port'])],text=True).strip())
                    yield forward,log_path
                except BaseException as e:
                    e.add_note(log_path.read_text());raise
                finally:
                    if pid:subprocess.run(['adb','shell','kill','-TERM',str(pid)],check=False)
                    try:process.wait(10)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
                    if forward:adb('forward','--remove','tcp:'+str(forward))

if __name__=='__main__':unittest.main(verbosity=2)
