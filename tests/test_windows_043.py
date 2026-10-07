"""Production Windows binary with a temporary, verified local CA in the CI user store."""
import contextlib,json,os,pathlib,ssl,subprocess,tempfile,time,unittest
from test_core import BIN
import test_expanded as old
from test_batch import PW
from test_repair_transport_042 import RepairTransportTests,CookiePeer
from test_portable_044 import PortableTransportTests

@unittest.skipUnless(os.name=='nt' and PW,'Windows CI only')
class WindowsRepairTransportTests(RepairTransportTests):
    test_randomized_noalpn_websocket_in_production_core = PortableTransportTests.test_randomized_noalpn_websocket_in_production_core
    @classmethod
    def certificate_store(cls,action):
        script=cls.directory/'certificate-store.ps1'
        script.write_text(r'''param([string]$File,[string]$Action)
$ErrorActionPreference='Stop'
$certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2($File)
$store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
try {
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    if ($Action -eq 'add') { $store.Add($certificate) } else { $store.Remove($certificate) }
} finally { $store.Close(); $certificate.Dispose() }
''',encoding='utf-8-sig')
        subprocess.run([PW,'-NoProfile','-File',str(script),'-File',str(cls.directory/'ca.der'),'-Action',action],capture_output=True,text=True,check=True,timeout=60)

    @classmethod
    def setUpClass(cls):
        old.ExpandedTests.setUpClass.__func__(cls)
        (cls.directory/'ca.der').write_bytes(ssl.PEM_cert_to_DER_cert(cls.ca.read_text()))
        try:cls.certificate_store('add')
        except BaseException:
            old.ExpandedTests.tearDownClass.__func__(cls)
            raise

    @classmethod
    def tearDownClass(cls):
        try:cls.certificate_store('remove')
        finally:old.ExpandedTests.tearDownClass.__func__(cls)

    @contextlib.contextmanager
    def core(self,uri):
        with tempfile.TemporaryDirectory(dir=self.directory) as td:
            td=pathlib.Path(td);ready=td/'ready.json';config=td/'node.ini';log_path=td/'core.log'
            # Production config: CA trust comes from the normal Windows store.
            config.write_text(f'node_uri={uri}\nlisten_port=0\nready_file={ready}\nconnect_timeout_ms=5000\nidle_timeout_ms=15000\n',encoding='utf-8')
            with log_path.open('w') as log:
                process=subprocess.Popen([str(BIN),'--config',str(config)],stdout=log,stderr=subprocess.STDOUT)
                try:
                    deadline=time.monotonic()+10
                    while not ready.exists():
                        if process.poll() is not None or time.monotonic()>deadline:raise AssertionError(log_path.read_text())
                        time.sleep(.02)
                    state=json.loads(ready.read_text());self.assertEqual(state['pid'],process.pid)
                    yield state['port'],log_path
                except BaseException as error:
                    time.sleep(.1);error.add_note(log_path.read_text());raise
                finally:
                    process.terminate()
                    try:process.wait(5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()

    def test_native_certificate_name_is_still_verified(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key)
        peer=CookiePeer('vless',tls=context)
        uri=old.ExpandedTests.uri(self,peer).replace('type=raw','type=ws').replace('security=none','security=tls').replace('sni=localhost','sni=wrong.invalid')+'&fp=native'
        try:
            with self.core(uri) as (port,log):
                old.original.CoreTests.socks(self,port,expected=1).close()
                time.sleep(.1)
                self.assertIn('TLS_CERTIFICATE_NAME',log.read_text())
        finally:peer.close()

if __name__=='__main__':unittest.main(verbosity=2)
