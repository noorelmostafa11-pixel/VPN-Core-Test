"""Controlled encrypted peers through real netstack/C++ protocol path."""
import base64, json, os, pathlib, socket, ssl, subprocess, tempfile, unittest
from urllib.parse import quote
import test_core as core
import test_expanded as peers
import test_reality as reality
import test_xhttp_modes as xhttp
from test_udp_sdk import UdpStreamPeer,ShadowsocksUdpPeer
BUILD=pathlib.Path(os.environ.get('VPN_NATIVE_BUILD',core.ROOT/'build/linux-amd64'))
PROBE=BUILD/('netstack-core-probe.exe' if os.name=='nt' else 'netstack-core-probe')
class EncryptedPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        core.CoreTests.setUpClass();cls.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        fixture=core.ROOT/('bin/xhttp-peer.exe' if os.name=='nt' else 'bin/xhttp-peer');fixture.parent.mkdir(exist_ok=True)
        subprocess.run(['go','build','-mod=vendor','-o',str(fixture.resolve()),'../tests/xhttp_peer.go'],cwd=core.ROOT/'tls-provider',check=True,timeout=120)
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
        credential=str(peers.ID) if proto in ('vless','vmess') else quote(peers.SECRET,safe='')
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
    def test_xhttp_encrypted_modes_and_separate_download(self):
        fixture=xhttp.XHttpTests();fixture.directory=core.CoreTests.directory
        for mode in ('stream-one','stream-up','packet-up'):
            for h2 in (False,True):
                for family in (4,6):
                    with self.subTest(mode=mode,h2=h2,ip=family):
                        with fixture.peer('vless','',mode,tls=True,h2=h2) as (uri,peer,log):
                            self.probe(uri,f'tcp{family}');self.assertEqual(peer.errors,[])
        for mode in ('stream-up','packet-up'):
            for h2 in (False,True):
                with self.subTest(separate=True,mode=mode,h2=h2):
                    with fixture.peer('vless','',mode,tls=True,h2=h2,extra={'_separate':True}) as (uri,peer,log):
                        self.probe(uri,'tcp4');self.assertEqual(peer.errors,[])
    def test_xhttp_bad_certificate_rejected(self):
        fixture=xhttp.XHttpTests();fixture.directory=core.CoreTests.directory
        with fixture.peer('vless','','stream-one',tls=True,h2=True) as (uri,peer,log):self.probe(uri,'tcp4',success=False,ca=False)
    def test_shadowsocks_authenticated_udp_both_families(self):
        for method in ('aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm'):
            for family in (4,6):
                peer=ShadowsocksUdpPeer(method);credential=base64.urlsafe_b64encode((method+':'+peer.password).encode()).decode().rstrip('=')
                try:self.probe(f'ss://{credential}@127.0.0.1:{peer.port}',f'udp{family}');self.assertEqual(peer.errors,[])
                finally:peer.close()
    def test_vmess_authenticated_tcp_and_tls_transports(self):
        for cipher in ('aes-128-gcm','chacha20-poly1305','none'):
            for transport in ('raw','websocket','grpc'):
                for family in (4,6):
                    with self.subTest(cipher=cipher,transport=transport,ip=family):
                        peer=peers.Peer('vmess',cipher=cipher,transport=transport,tls_context=self.context)
                        peer.expected_vmess_destination=b'\1\1\xbb'+(b'\1'+socket.inet_aton('203.0.113.9') if family==4 else b'\3'+socket.inet_pton(socket.AF_INET6,'2001:db8::9'))
                        uri=self.uri('vmess',peer.port,transport)+'&encryption='+cipher
                        try:self.probe(uri,f'tcp{family}');self.assertEqual(peer.errors,[])
                        finally:peer.close()
    def test_reality_authenticated_tcp_both_families_and_bad_auth(self):
        for family in (4,6):
            for corrupt in (False,True):
                peer=reality.RealityPeer(corrupt=corrupt)
                try:self.probe(reality.RealityTests.uri(peer),f'tcp{family}',success=not corrupt);self.assertEqual(peer.authenticated,1);self.assertEqual(peer.errors,[])
                finally:peer.close()
if __name__=='__main__':unittest.main()
