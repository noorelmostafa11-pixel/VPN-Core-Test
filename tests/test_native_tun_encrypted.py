"""Controlled encrypted peers through real netstack/C++ protocol path."""
import base64, json, os, pathlib, ssl, subprocess, tempfile, unittest
from urllib.parse import quote
import test_core as core
import test_expanded as peers
from test_udp_sdk import UdpStreamPeer,ShadowsocksUdpPeer
BUILD=pathlib.Path(os.environ.get('VPN_NATIVE_BUILD',core.ROOT/'build/linux-amd64'))
PROBE=BUILD/('netstack-core-probe.exe' if os.name=='nt' else 'netstack-core-probe')
class EncryptedPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        core.CoreTests.setUpClass();cls.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key);cls.context.set_alpn_protocols(['h2','http/1.1'])
    @classmethod
    def tearDownClass(cls):core.CoreTests.tearDownClass()
    def probe(self,uri,mode,success=True,ca=True):
        with tempfile.TemporaryDirectory() as td:
            cfg=pathlib.Path(td)/'node.ini';cfg.write_text('node_uri='+uri+'\nconnect_timeout_ms=2000\nidle_timeout_ms=10000\n'+('tls_ca_file='+str(core.CoreTests.ca)+'\n' if ca else ''))
            result=subprocess.run([str(PROBE.resolve()),'--config',str(cfg),mode],capture_output=True,text=True,timeout=20)
            if success:
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                row=json.loads(result.stdout.splitlines()[-1]);self.assertEqual(row['status'],'PASS')
            else:self.assertNotEqual(result.returncode,0,'Invalid certificate accepted')
    def uri(self,proto,port,transport):
        credential=str(peers.ID) if proto=='vless' else quote(peers.SECRET,safe='')
        return f'{proto}://{credential}@127.0.0.1:{port}?security=tls&type={transport}&sni=localhost&path=/test&serviceName=test&fp=chrome'
    def test_tcp_encrypted_protocols_transports_both_families(self):
        for proto in ('vless','trojan'):
            for transport in ('raw','websocket','httpupgrade','grpc'):
                for family in (4,6):
                    with self.subTest(protocol=proto,transport=transport,ip=family):
                        peer=peers.Peer(proto,transport=transport,tls_context=self.context)
                        try:self.probe(self.uri(proto,peer.port,transport),f'tcp{family}');self.assertEqual(peer.errors,[])
                        finally:peer.close()
    def test_udp_encrypted_protocols_transports_both_families(self):
        for proto in ('vless','trojan'):
            for transport in ('raw','websocket','httpupgrade','grpc'):
                for family in (4,6):
                    with self.subTest(protocol=proto,transport=transport,ip=family):
                        peer=UdpStreamPeer(proto,transport=transport,tls_context=self.context)
                        try:self.probe(self.uri(proto,peer.port,transport),f'udp{family}');self.assertEqual(peer.errors,[])
                        finally:peer.close()
    def test_wrong_name_and_untrusted_root_fail_closed(self):
        for mode in ('tcp4','udp6'):
            for bad_name in (True,False):
                peer=peers.Peer('vless',tls_context=self.context)
                try:self.probe(self.uri('vless',peer.port,'raw').replace('sni=localhost','sni=wrong.invalid') if bad_name else self.uri('vless',peer.port,'raw'),mode,success=False,ca=bad_name)
                finally:peer.close()
    def test_shadowsocks_authenticated_udp_both_families(self):
        for method in ('aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm'):
            for family in (4,6):
                peer=ShadowsocksUdpPeer(method);credential=base64.urlsafe_b64encode((method+':'+peer.password).encode()).decode().rstrip('=')
                try:self.probe(f'ss://{credential}@127.0.0.1:{peer.port}',f'udp{family}');self.assertEqual(peer.errors,[])
                finally:peer.close()
if __name__=='__main__':unittest.main()
