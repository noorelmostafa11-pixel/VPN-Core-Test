"""Independent WebSocket/early-data/Mux.Cool peer around crypto test oracles."""
import base64
import concurrent.futures
import hashlib
import random
import socket
import ssl
import struct
import time
import unittest
from urllib.parse import quote
import test_expanded as old
from test_core import exact

class WebSocket(old.Wrapped):
    def __init__(self, sock, peer):
        self.sock, self.transport, self.bad = sock, 'websocket', False
        self.buffer, self.grpc_buffer, self.ended = bytearray(), bytearray(), False
        request = bytearray()
        while not request.endswith(b'\r\n\r\n'):
            request += exact(sock, 1)
            if len(request) > 65536: raise ValueError('request too large')
        lines = request.decode().split('\r\n')
        if lines[0] != 'GET '+peer.path+' HTTP/1.1': raise ValueError('escaped request path')
        headers = {line.split(':',1)[0].lower():line.split(':',1)[1].strip() for line in lines[1:] if ':' in line}
        data = headers.get(peer.early_header.lower(), '')
        if peer.early_size:
            if not data: raise ValueError('missing early data')
            decoded = base64.urlsafe_b64decode(data+'='*((-len(data))%4))
            if len(decoded)>peer.early_size or '=' in data or '+' in data or '/' in data: raise ValueError('early encoding')
            self.buffer.extend(decoded)
            peer.early_lengths.append(len(decoded))
        elif data: raise ValueError('unexpected early data')
        if peer.plugin and headers.get('host') != 'localhost': raise ValueError('plugin Host')
        key=headers['sec-websocket-key']
        accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        response=b'HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: '+accept+b'\r\n'
        if peer.bad=='subprotocol':response+=b'Sec-WebSocket-Protocol: unexpected\r\n'
        elif data and peer.early_header.lower()=='sec-websocket-protocol':response+=b'Sec-WebSocket-Protocol: '+data.encode()+b'\r\n'
        sock.sendall(response+b'\r\n')
    def settimeout(self,value):self.sock.settimeout(value)
    def close(self):self.sock.close()

class Mux:
    def __init__(self,wire,peer):self.wire,self.peer=wire,peer;self.buffer=bytearray();self.ended=False;self.started=False
    def recv(self,n):
        while not self.buffer and not self.ended:
            try: length=int.from_bytes(exact(self.wire,2),'big')
            except EOFError:self.ended=True;break
            if not 4<=length<=512:raise ValueError('mux length')
            metadata=exact(self.wire,length);session,status,options=struct.unpack('!HBB',metadata[:4])
            if session!=1 or options & ~3:raise ValueError('mux metadata')
            if not self.started:
                expected=b'\1'+self.peer.port.to_bytes(2,'big')+b'\1\x7f\0\0\1'
                if status!=1 or metadata[4:]!=expected:raise ValueError('mux TCP destination')
                self.started=True
            elif status not in (2,3) or length!=4:raise ValueError('mux continuation')
            if options&1:self.buffer.extend(exact(self.wire,int.from_bytes(exact(self.wire,2),'big')))
            if status==3:self.ended=True
        data=bytes(self.buffer[:n]);del self.buffer[:n];return data
    def sendall(self,data):
        if self.peer.bad=='mux_session':self.wire.sendall(b'\0\4\0\2\2\0');return
        if self.peer.bad=='mux_new':self.wire.sendall(b'\0\4\0\1\1\0');return
        if self.peer.bad=='mux_error':self.wire.sendall(b'\0\4\0\1\3\2');return
        # Keepalive uses an unrelated session ID. Split both length and metadata
        # over separate fragmented WebSocket messages; data is a byte stream.
        keep=b'\0\4\x43\x21\4\1\0\3xyz'
        frame=keep+b'\0\4\0\1\2\1'+len(data).to_bytes(2,'big')+data
        for offset in (0,1,3,6):
            end={0:1,1:3,3:6,6:len(frame)}[offset]
            self.wire.sendall(frame[offset:end])
    def settimeout(self,value):self.wire.settimeout(value)
    def close(self):self.wire.close()

class Peer(old.Peer):
    def __init__(self,protocol,cipher='',*,plugin=False,mux=False,tls=None,early=0,header='Sec-WebSocket-Protocol',path='/test',bad=''):
        self.plugin,self.mux,self.context=plugin,mux,tls
        self.early_size,self.early_header,self.early_lengths=early,header,[]
        self.bad=bad
        super().__init__(protocol,cipher,'raw',path=path)
    def handle(self,raw):
        sock=raw
        try:
            raw.settimeout(10)
            if self.context:sock=self.context.wrap_socket(raw,server_side=True)
            wire=WebSocket(sock,self)
            if self.bad=='subprotocol':return
            if self.mux:wire=Mux(wire,self)
            super().handle(wire)
        except (EOFError,OSError,ssl.SSLError):pass
        except Exception as e:self.errors.append(repr(e))
        finally:sock.close();raw.close()

class WebSocketPluginTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    socks=old.ExpandedTests.socks
    def uri(self,p,plugin_options=''):
        uri=old.ExpandedTests.uri(self,p)
        if p.plugin:
            value='v2ray-plugin;mode=websocket;host=localhost;path=/test'+plugin_options
            uri+='&plugin='+quote(value,safe='')
        else:uri=uri.replace('type=raw','type=ws')
        if p.early_size:uri+=f'&ed={p.early_size}&eh='+quote(p.early_header,safe='')
        return uri
    def exchange(self,p,uri=None,length=240017,connections=1):
        try:
            with self.core(uri or self.uri(p)) as (port,log):
                def run(seed):
                    with self.socks(port) as s:
                        self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                        data=random.Random(seed).randbytes(length);s.sendall(data)
                        self.assertEqual(hashlib.sha256(exact(s,len(data))).digest(),hashlib.sha256(data).digest())
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(run,range(connections)))
            self.assertEqual(p.errors,[])
        finally:p.close()
    def test_01_early_all_protocols(self):
        for protocol,cipher in [('vless',''),('trojan',''),('vmess','aes-128-gcm'),('ss','chacha20-ietf-poly1305')]:
            for size in (7,2048):
                with self.subTest(protocol=protocol,early=size):self.exchange(Peer(protocol,cipher,early=size),connections=2)
    def test_02_early_alias_path_and_custom_header(self):
        for header in ('sec-websocket-protocol','X-Proxy-Early'):
            p=Peer('vless',early=16,header=header)
            uri=self.uri(p).replace('&ed=16','').replace('path=%2Ftest','path='+quote('/test?ed=16',safe=''))
            self.exchange(p,uri)
        p=Peer('vmess','chacha20-poly1305',early=2048)
        self.exchange(p,self.uri(p).replace('&ed=2048','&max_early_data=2048'))
    def test_03_plugin_default_mux_parallel(self):
        for cipher in ('aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305'):
            with self.subTest(cipher=cipher):self.exchange(Peer('ss',cipher,plugin=True,mux=True),connections=8)
    def test_04_plugin_mux_zero_and_four(self):
        for count in (0,4):
            p=Peer('ss','aes-128-gcm',plugin=True,mux=bool(count))
            self.exchange(p,self.uri(p,f';mux={count}'),connections=4)
    def test_05_plugin_tls_verified_and_early_mux(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key)
        context.set_alpn_protocols(['http/1.1'])
        for fp in ('chrome','firefox','native'):
            p=Peer('ss','aes-256-gcm',plugin=True,mux=True,tls=context,early=2048)
            self.exchange(p,self.uri(p,';tls')+'&fp='+fp,connections=2)
    def test_06_plugin_wrong_certificate_name(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key)
        p=Peer('ss','aes-128-gcm',plugin=True,mux=True,tls=context)
        try:
            uri=self.uri(p,';tls;skip-cert-verify').replace('host%3Dlocalhost','host%3Dwrong.example')+'&fp=chrome&allowInsecure=1'
            with self.core(uri) as (port,log):
                with socket.create_connection(('127.0.0.1',port),5) as s:
                    s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0')
                    s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(s,10)[1],0)
                time.sleep(.03);self.assertIn('TLS_FAILED',log.read_text())
        finally:p.close()
    def test_07_bad_mux_metadata(self):
        for bad in ('mux_session','mux_new','mux_error'):
            p=Peer('ss','aes-128-gcm',plugin=True,mux=True,bad=bad)
            try:
                with self.core(self.uri(p)) as (port,log):
                    with self.socks(port) as s:
                        try:self.assertEqual(s.recv(100),b'')
                        except ConnectionResetError:pass
                    time.sleep(.04);self.assertIn('MUX_',log.read_text())
            finally:p.close()
    def test_08_unsolicited_subprotocol(self):
        p=Peer('vless',early=2048,bad='subprotocol')
        try:
            with self.core(self.uri(p)) as (port,log):
                with socket.create_connection(('127.0.0.1',port),5) as s:
                    s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0')
                    s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(s,10)[1],0)
                time.sleep(.03);self.assertIn('WEBSOCKET_PROTOCOL',log.read_text())
        finally:p.close()
    def test_09_path_escaping(self):
        p=Peer('vless',path='/test%20space%23fragment/%D9%85?query=some%20text')
        raw='/test space#fragment/م?query=some text'
        self.exchange(p,self.uri(p).replace('path=%2Ftest','path='+quote(raw,safe='')))

    def test_10_nonnumeric_path_early_data(self):
        import json,subprocess,pathlib
        from test_core import ROOT,BIN
        p=Peer('vless',path='/test?keep=1')
        uri=self.uri(p).replace('path=%2Ftest','path='+quote('/test?ed=non-numeric&keep=1',safe=''))
        cfg=pathlib.Path(self.directory)/'normalization.ini';cfg.write_text('node_uri='+uri+'\n')
        row=json.loads(subprocess.check_output([str(BIN),'--config',str(cfg),'--inspect-config'],text=True))
        self.assertTrue(row['websocket_path_ed_invalid']);self.assertEqual(row['websocket_early_data'],0)
        self.exchange(p,uri)

if __name__=='__main__':unittest.main(verbosity=2)
