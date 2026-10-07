"""Independent RPRX peer; outer TLS records use the Python TLS13 oracle."""
import datetime,hashlib,os,random,socket,ssl,struct,threading,time,unittest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
import test_expanded as old
from test_core import exact
from test_tls_profiles import hello_fields
from tls13_peer import TLS13Peer

def record_size(b):
    if len(b)>=5 and b[:3]==b'\x17\x03\x03':return 5+int.from_bytes(b[3:5],'big')
    return 0
class LegacyWire:
    def __init__(self,outer,direct):self.outer=outer;self.socket=outer.socket;self.direct=direct;self.up=False;self.down=False;self.ur=0;self.dr=0;self.buffer=bytearray();self.header=bytearray();self.left=0
    def recv(self,n):
        if self.buffer:out=bytes(self.buffer[:n]);del self.buffer[:n];return out
        if not self.up:
            data=self.outer.recv(n)
            if not self.ur:self.ur=record_size(data)
            if self.ur:self.ur-=len(data);self.up=self.ur==0
            return data
        if self.direct:return self.socket.recv(n)
        h=exact(self.socket,5);size=record_size(h)
        if not size:raise ValueError('legacy raw header')
        wire=h+exact(self.socket,size-5);self.outer.receive_keys.sequence+=1
        out=wire[:n];self.buffer+=wire[n:];return out
    def raw_send(self,data):
        if not self.direct:
            tail=data
            while tail:
                if not self.left:
                    n=min(5-len(self.header),len(tail));self.header+=tail[:n];tail=tail[n:]
                    if len(self.header)<5:break
                    size=record_size(self.header)
                    if not size:raise ValueError('legacy raw write')
                    self.header.clear();self.left=size-5;self.outer.send_keys.sequence+=1
                n=min(self.left,len(tail));self.left-=n;tail=tail[n:]
        self.socket.sendall(data)
    def sendall(self,data):
        if self.down:self.raw_send(data);return
        if not self.dr:self.dr=record_size(data)
        if not self.dr:self.outer.sendall(data);return
        n=min(self.dr,len(data));self.outer.sendall(data[:n]);self.dr-=n
        if not self.dr:self.down=True
        if n<len(data):self.raw_send(data[n:])

class LegacyPeer(old.Peer):
    def __init__(self,context,key,certificate,flow,protocol='vless',inner=True):self.context=context;self.key=key;self.certificate=certificate;self.flow=flow;self.inner=inner;self.transitions=0;super().__init__(protocol,tls_context=True)
    def handle(self,raw):
        try:
            raw.settimeout(8);head=exact(raw,5);hello=exact(raw,int.from_bytes(head[3:5],'big'));_,extensions=hello_fields(head+hello)
            outer=TLS13Peer(raw,hello,dict(extensions)[51],self.certificate,self.key)
            wire=LegacyWire(outer,self.flow!='xtls-rprx-origin')
            if self.protocol=='vless':
                if exact(wire,17)!=b'\0'+old.ID.bytes:raise ValueError('VLESS auth')
                n=exact(wire,1)[0];flow=self.flow.replace('xtls-rprx-splice','xtls-rprx-direct').encode()
                if exact(wire,n)!=b'\x0a'+bytes([len(flow)])+flow:raise ValueError('legacy addon')
                if exact(wire,1)!=b'\1':raise ValueError('command')
                exact(wire,2);at=exact(wire,1)[0];exact(wire,exact(wire,1)[0] if at==2 else 4 if at==1 else 16);wire.sendall(b'\0\0')
            else:
                if exact(wire,56)!=hashlib.sha224(old.SECRET.encode()).hexdigest().encode() or exact(wire,3)!=b'\r\n\1':raise ValueError('Trojan header')
                at=exact(wire,1)[0];exact(wire,exact(wire,1)[0] if at==3 else 4 if at==1 else 16);exact(wire,4)
            if not self.inner:
                wire.sendall(old.HELLO)
                while True:
                    b=wire.recv(1001)
                    if not b:break
                    wire.sendall(b)
                return
            incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();inner=self.context.wrap_bio(incoming,outgoing,server_side=True)
            while True:
                try:inner.do_handshake();break
                except ssl.SSLWantReadError:
                    data=outgoing.read()
                    if data:wire.sendall(data)
                    incoming.write(wire.recv(65536))
            self.transitions+=1;inner.write(old.HELLO);wire.sendall(outgoing.read())
            while True:
                try:
                    data=inner.read(16384)
                    if not data:break
                    inner.write(data);wire.sendall(outgoing.read())
                except ssl.SSLWantReadError:
                    data=outgoing.read()
                    if data:wire.sendall(data)
                    data=wire.recv(16384)
                    if not data:break
                    incoming.write(data)
        except (EOFError,OSError,ssl.SSLError):pass
        except Exception as e:self.errors.append(repr(e))
        finally:raw.close()
class LegacyXTLSTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core;socks=old.ExpandedTests.socks
    def exchange(self,flow,fp='chrome',protocol='vless',inner=True):
        key=ed25519.Ed25519PrivateKey.generate();name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.datetime.now(datetime.timezone.utc)
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(47).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False).sign(key,None)
        ca=self.directory/'legacy-ca.pem';ca.write_bytes(self.ca.read_bytes()+cert.public_bytes(serialization.Encoding.PEM));original_ca=self.ca;self.ca=ca
        p=LegacyPeer(self.context,key,cert.public_bytes(serialization.Encoding.DER),flow,protocol,inner)
        try:
            credential=str(old.ID) if protocol=='vless' else old.SECRET
            uri=f'{protocol}://{credential}@127.0.0.1:{p.port}?security=xtls&type=raw&sni=localhost&flow={flow}&fp={fp}'
            with self.core(uri) as (port,log):
                try:sock=self.socks(port)
                except Exception:raise AssertionError(log.read_text()+str(p.errors))
                if inner:
                    context=ssl.create_default_context(cafile=original_ca);context.minimum_version=ssl.TLSVersion.TLSv1_3
                    try:sock=context.wrap_socket(sock,server_hostname='localhost')
                    except Exception:raise AssertionError(log.read_text()+str(p.errors))
                with sock:
                    self.assertEqual(exact(sock,len(old.HELLO)),old.HELLO);data=random.Random(782).randbytes(300019)
                    # One owner per OpenSSL SSL object. Concurrent send/read on
                    # the same SSLSocket is not a valid interoperability oracle.
                    try:
                        sock.sendall(data)
                        self.assertEqual(hashlib.sha256(exact(sock,len(data))).digest(),hashlib.sha256(data).digest())
                    except Exception:raise AssertionError(log.read_text()+str(p.errors))
                self.assertNotIn('failed phase=',log.read_text())
            self.assertEqual(p.errors,[]);self.assertEqual(p.transitions,int(inner))
        finally:p.close();self.ca=original_ca
    def test_01_direct_profiles_and_protocols(self):
        for fp in ('chrome','firefox','native'):
            for protocol in ('vless','trojan'):
                with self.subTest(fp=fp,protocol=protocol):self.exchange('xtls-rprx-direct',fp,protocol)
    def test_02_origin_and_splice(self):
        for flow in ('xtls-rprx-origin','xtls-rprx-splice'):
            with self.subTest(flow=flow):self.exchange(flow)
    def test_03_opaque_payload_keeps_outer_tls(self):self.exchange('xtls-rprx-direct',inner=False)
if __name__=='__main__':unittest.main(verbosity=2)
