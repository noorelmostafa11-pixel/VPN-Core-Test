"""Production POSIX core: verified TLS, project protocols, and shared C API."""
import contextlib,ctypes,json,os,pathlib,ssl,subprocess,tempfile,threading,time,unittest
from test_core import BIN,ROOT
import test_expanded as old
from test_repair_transport_042 import RepairTransportTests,CookiePeer

class PortableTransportTests(RepairTransportTests):
    @contextlib.contextmanager
    def core(self,uri):
        with tempfile.TemporaryDirectory(dir=self.directory) as td:
            td=pathlib.Path(td);ready=td/'ready.json';cfg=td/'node.ini';log_path=td/'core.log'
            cfg.write_text(f'node_uri={uri}\nlisten_port=0\nready_file={ready}\nconnect_timeout_ms=5000\nidle_timeout_ms=15000\n')
            env=dict(os.environ,SSL_CERT_FILE=str(self.ca))
            with log_path.open('w') as log:
                process=subprocess.Popen([str(BIN),'--config',str(cfg)],env=env,stdout=log,stderr=subprocess.STDOUT)
                try:
                    deadline=time.monotonic()+10
                    while not ready.exists():
                        if process.poll() is not None or time.monotonic()>deadline:raise AssertionError(log_path.read_text())
                        time.sleep(.02)
                    self.assertEqual(json.loads(ready.read_text())['pid'],process.pid)
                    yield json.loads(ready.read_text())['port'],log_path
                except BaseException as e:
                    e.add_note(log_path.read_text());raise
                finally:
                    process.terminate()
                    try:process.wait(5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()

    def test_certificate_name_remains_verified(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key)
        peer=CookiePeer('vless',tls=context)
        uri=old.ExpandedTests.uri(self,peer).replace('type=raw','type=ws').replace('security=none','security=tls').replace('sni=localhost','sni=wrong.invalid')+'&fp=native'
        try:
            with self.core(uri) as (port,log):
                old.original.CoreTests.socks(self,port,expected=1).close();time.sleep(.1)
                self.assertIn('TLS_CERTIFICATE_NAME',log.read_text())
        finally:peer.close()

    def test_all_four_raw_protocols(self):
        for proto,cipher in [('vless',''),('trojan',''),('vmess','aes-128-gcm'),('ss','aes-256-gcm')]:
            with self.subTest(protocol=proto):
                peer=old.Peer(proto,cipher,'raw',self.context)
                try:
                    with self.core(old.ExpandedTests.uri(self,peer)) as (port,log):
                        with self.socks(port) as s:
                            self.assertEqual(old.original.exact(s,len(old.HELLO)),old.HELLO)
                            s.sendall(b'portable core');self.assertEqual(old.original.exact(s,13),b'portable core')
                    self.assertEqual(peer.errors,[])
                finally:peer.close()

class SharedCoreTests(unittest.TestCase):
    def test_run_stop_restart_and_module_relative_provider(self):
        # The library is loaded outside the executable/current-working directory.
        name='vpn-core.dll' if os.name=='nt' else 'libvpn-core.so'
        lib=ctypes.CDLL(str(BIN.parent/name))
        lib.vpn_core_version.restype=ctypes.c_char_p
        self.assertEqual(lib.vpn_core_version().decode(),(ROOT/'VERSION').read_text().strip())
        lib.vpn_core_run.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_char_p)]
        def invoke(*args):
            values=(ctypes.c_char_p*(len(args)+1))(b'vpn-core',*[str(v).encode() for v in args])
            return lib.vpn_core_run(len(values),values)
        self.assertEqual(invoke('--self-test'),0);self.assertEqual(invoke('--check-components'),0)
        with tempfile.TemporaryDirectory() as td:
            for index in range(2):
                ready=pathlib.Path(td)/f'ready-{index}.json';cfg=pathlib.Path(td)/'node.ini'
                cfg.write_text(f'node_uri=vless://{old.ID}@127.0.0.1:443?security=none&type=raw\nlisten_port=0\nready_file={ready}\n')
                result=[];thread=threading.Thread(target=lambda:result.append(invoke('--config',cfg)),daemon=True);thread.start()
                try:
                    end=time.monotonic()+10
                    while not ready.exists() and thread.is_alive() and time.monotonic()<end:time.sleep(.02)
                    self.assertTrue(ready.exists());self.assertEqual(invoke('--self-test'),2)
                finally:
                    lib.vpn_core_stop();thread.join(10)
                self.assertFalse(thread.is_alive());self.assertEqual(result,[0])

if __name__=='__main__':unittest.main(verbosity=2)
