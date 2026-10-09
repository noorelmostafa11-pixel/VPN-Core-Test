"""Independent local positive/negative peers for F1, F2 and F3."""
import base64, json, socket, ssl, time, unittest
import test_core as original
import test_expanded as peers
import test_reality as reality

class CompatibilityRepairTests(unittest.TestCase):
    setUpClass=classmethod(peers.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(peers.ExpandedTests.tearDownClass.__func__)
    core=peers.ExpandedTests.core
    socks=peers.ExpandedTests.socks

    def exchange(self,uri):
        with self.core(uri) as (port,log):
            with self.socks(port) as client:
                self.assertEqual(original.exact(client,len(peers.HELLO)),peers.HELLO)
                payload=b'verified local data'*2000
                client.sendall(payload)
                self.assertEqual(original.exact(client,len(payload)),payload)

    def rejected(self,uri,reason):
        with self.core(uri) as (port,log):
            with socket.create_connection(('127.0.0.1',port),5) as client:
                client.settimeout(5);client.sendall(b'\x05\x01\x00')
                self.assertEqual(original.exact(client,2),b'\x05\x00')
                client.sendall(b'\x05\x01\x00\x03\x0cexample.test\x01\xbb')
                self.assertNotEqual(original.exact(client,10)[1],0)
            time.sleep(.05)
            self.assertIn(reason,log.read_text())

    def test_f1_missing_empty_and_json_null_sni_transfer_data(self):
        for variant in ('missing','empty','json_null'):
            with self.subTest(variant=variant):
                protocol='vmess' if variant=='json_null' else 'vless'
                peer=peers.Peer(protocol,'none' if protocol=='vmess' else '',tls_context=self.context)
                try:
                    if variant=='json_null':
                        value={'v':'2','add':'127.0.0.1','port':str(peer.port),'id':str(peers.ID),'aid':'0','scy':'none','net':'tcp','type':'none','tls':'tls','sni':None,'fp':'chrome'}
                        uri='vmess://'+base64.b64encode(json.dumps(value).encode()).decode()
                    else:
                        uri=f'vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&type=tcp&fp=chrome'
                        if variant=='empty':uri+='&sni='
                    self.exchange(uri)
                finally:peer.close()

    def test_f1_explicit_wrong_name_and_wrong_pin_still_rejected(self):
        for query,reason in [('sni=wrong.example.invalid','TLS_CERTIFICATE_NAME'),('sni=&pcs='+'00'*32,'TLS_CERTIFICATE_PIN')]:
            with self.subTest(reason=reason):
                peer=peers.Peer('vless',tls_context=self.context)
                try:self.rejected(f'vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&type=tcp&fp=chrome&'+query,reason)
                finally:peer.close()

    def test_f1_reality_empty_name_preserves_authentication(self):
        for corrupt in (False,True):
            with self.subTest(corrupt=corrupt):
                peer=reality.RealityPeer(corrupt=corrupt)
                try:
                    uri=reality.RealityTests.uri(peer).replace('sni=localhost','sni=')
                    if corrupt:self.rejected(uri,'REALITY_AUTHENTICATION')
                    else:self.exchange(uri)
                finally:peer.close()

    def test_f2_upgrade_host_fallback_and_explicit_host_preserved(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(original.CoreTests.cert,original.CoreTests.key)
        context.set_alpn_protocols(['http/1.1'])
        for transport in ('websocket','httpupgrade'):
            for host in ('','localhost','explicit.invalid'):
                with self.subTest(transport=transport,host=host):
                    observations=[]
                    class ObservedSocket:
                        def __init__(self,s):self.sock=s;self.request=bytearray();self.done=False
                        def recv(self,n):
                            data=self.sock.recv(n)
                            if not self.done:
                                self.request.extend(data)
                                if self.request.endswith(b'\r\n\r\n'):
                                    self.done=True
                                    actual=next(x.split(':',1)[1].strip() for x in self.request.decode().split('\r\n') if x.lower().startswith('host:'))
                                    observations.append(actual)
                                    if actual!='localhost':
                                        self.sock.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
                                        raise EOFError('fixture virtual host rejected')
                            return data
                        def __getattr__(self,name):return getattr(self.sock,name)
                    class ObservedContext:
                        def wrap_socket(self,raw,**kw):return ObservedSocket(context.wrap_socket(raw,**kw))
                    peer=peers.Peer('vless',transport=transport,tls_context=ObservedContext())
                    try:
                        uri=f'vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&type={transport}&path=/test&sni=localhost&fp=chrome'
                        if host:uri+='&host='+host
                        if host=='explicit.invalid':self.rejected(uri,'HTTP_UPGRADE_STATUS')
                        else:self.exchange(uri)
                        self.assertEqual(observations,[host or 'localhost'])
                    finally:peer.close()

    def test_f3_reality_grpc_authentication_and_http2_data(self):
        original_peer=reality.TLS13Peer
        class GrpcWire(peers.Wrapped):
            def close(self):self.sock.close()
        def wrapped(*args,**kw):return GrpcWire(original_peer(*args,**kw),'grpc',path='/test/Tun')
        reality.TLS13Peer=wrapped
        try:
            peer=reality.RealityPeer()
            try:
                self.exchange(reality.RealityTests.uri(peer).replace('type=tcp','type=grpc')+'&serviceName=test')
                self.assertEqual(peer.authenticated,1)
            finally:peer.close()
        finally:reality.TLS13Peer=original_peer

    def test_f3_wrong_reality_authentication_still_rejected(self):
        peer=reality.RealityPeer(corrupt=True)
        try:self.rejected(reality.RealityTests.uri(peer).replace('type=tcp','type=grpc')+'&serviceName=test','REALITY_AUTHENTICATION')
        finally:peer.close()

    def test_f3_ordinary_tls_grpc_still_requires_h2(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(original.CoreTests.cert,original.CoreTests.key)
        context.set_alpn_protocols(['http/1.1'])
        peer=peers.Peer('vless',transport='grpc',tls_context=context)
        try:self.rejected(f'vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&type=grpc&sni=localhost&fp=chrome','ALPN_CARRIER_INCOMPATIBLE')
        finally:peer.close()

if __name__=='__main__':unittest.main()
