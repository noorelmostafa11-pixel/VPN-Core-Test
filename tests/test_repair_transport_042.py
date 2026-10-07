"""Independent TLS/WebSocket peer prefers h2 and sends valid repeated fields."""
import hashlib,random,ssl,unittest,socket,time
import test_ws_plugins as ws
import test_expanded as old
from test_core import exact
from test_batch import Service

class CookieSocket:
    def __init__(self,sock):self.sock=sock
    def __getattr__(self,key):return getattr(self.sock,key)
    def sendall(self,data):
        if data.startswith(b'HTTP/1.1 101 '):
            data=data.replace(b'Connection: upgrade\r\n',b'Connection: keep-alive\r\nConnection: Upgrade\r\nSet-Cookie: a=one\r\nSet-Cookie: b=two\r\n')
        return self.sock.sendall(data)
class CookiePeer(ws.Peer):
    def handle(self,raw):
        sock=raw
        try:
            raw.settimeout(10);sock=self.context.wrap_socket(raw,server_side=True);self.alpn=sock.selected_alpn_protocol()
            wire=ws.WebSocket(CookieSocket(sock),self);old.Peer.handle(self,wire)
        except (EOFError,OSError,ssl.SSLError):pass
        except Exception as e:self.errors.append(repr(e))
        finally:sock.close();raw.close()
class RepairTransportTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    socks=old.ExpandedTests.socks
    def test_no_alpn_server_keeps_existing_http1_compatibility(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key)
        p=CookiePeer('vless',tls=context)
        uri=old.ExpandedTests.uri(self,p).replace('type=raw','type=ws').replace('security=none','security=tls')+'&alpn=h2&fp=chrome'
        try:
            with self.core(uri) as (port,log):
                with self.socks(port) as s:
                    self.assertEqual(exact(s,len(old.HELLO)),old.HELLO);s.sendall(b'unchanged');self.assertEqual(exact(s,9),b'unchanged')
            self.assertIsNone(p.alpn);self.assertEqual(p.errors,[])
        finally:p.close()
    def test_negotiated_h2_is_rejected_before_http1_bytes(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key);context.set_alpn_protocols(['h2'])
        received=[]
        def handler(raw):
            with context.wrap_socket(raw,server_side=True) as s:
                try:received.append(s.recv(1))
                except (OSError,ssl.SSLError):pass
        p=Service(handler)
        uri=f'vless://{old.ID}@127.0.0.1:{p.port}?type=ws&security=tls&sni=localhost&alpn=h2&fp=chrome'
        try:
            with self.core(uri) as (port,log):
                with socket.create_connection(('127.0.0.1',port),5) as s:
                    s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0');s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(s,10)[1],0)
                time.sleep(.1);self.assertIn('ALPN_CARRIER_INCOMPATIBLE',log.read_text())
            self.assertTrue(all(not b for b in received));self.assertEqual(p.errors,[])
        finally:p.close()
    def test_ws_h1_selection_repeated_cookies_all_protocols(self):
        for protocol,cipher in [('vless',''),('trojan',''),('vmess','aes-128-gcm'),('ss','aes-256-gcm')]:
            for profile in ['native','chrome']:
                with self.subTest(protocol=protocol,profile=profile):
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key);context.set_alpn_protocols(['h2','http/1.1'])
                    p=CookiePeer(protocol,cipher,tls=context)
                    uri=old.ExpandedTests.uri(self,p).replace('type=raw','type=ws').replace('security=none','security=tls')+'&alpn=h2,http%2F1.1&fp='+profile
                    try:
                        with self.core(uri) as (port,log):
                            with self.socks(port) as s:
                                self.assertEqual(exact(s,len(old.HELLO)),old.HELLO);data=random.Random(4).randbytes(65537);s.sendall(data);self.assertEqual(hashlib.sha256(exact(s,len(data))).digest(),hashlib.sha256(data).digest())
                        self.assertEqual(p.alpn,'http/1.1');self.assertEqual(p.errors,[])
                    finally:p.close()
