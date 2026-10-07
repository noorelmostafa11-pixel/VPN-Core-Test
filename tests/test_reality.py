"""Independent REALITY authentication peer over Python/OpenSSL TLS 1.3.

The fixture authenticates the encrypted ClientHello session identifier, then
issues a session-bound Ed25519 certificate. No VPN engine is used by the test.
"""
import base64
import concurrent.futures
import datetime
import hashlib
import hmac
import pathlib
import random
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
import test_expanded as old
from test_core import exact, ROOT
from test_tls_profiles import hello_fields
from tls13_peer import TLS13Peer


class RealityPeer(old.Peer):
    def __init__(self, corrupt=False, ordinary=False, pq=False, bad_pq=False, bad_verify=False, bad_finished=False):
        self.private=x25519.X25519PrivateKey.generate()
        self.public=self.private.public_key().public_bytes_raw()
        self.authenticated=0
        self.corrupt_auth=corrupt
        self.ordinary=ordinary
        self.bad_pq,self.bad_verify,self.bad_finished=bad_pq,bad_verify,bad_finished
        self.signer=None
        if pq:
            self.signer=subprocess.Popen([str(ROOT/'bin/mldsa-signer')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            self.pq_public=self.signer.stdout.readline().strip()
        super().__init__('vless',tls_context=True)

    def handle(self, raw):
        sock=raw
        try:
            raw.settimeout(8)
            until=time.monotonic()+5
            while time.monotonic()<until:
                wire=raw.recv(65536,socket.MSG_PEEK)
                if len(wire)>=5 and len(wire)>=5+int.from_bytes(wire[3:5],'big'):break
                time.sleep(.001)
            size=int.from_bytes(wire[3:5],'big')
            hello=wire[5:5+size]
            if hello[0]!=1 or int.from_bytes(hello[1:4],'big')!=len(hello)-4:raise ValueError('ClientHello length')
            random_bytes=hello[6:38]
            if hello[38]!=32:raise ValueError('REALITY session id length')
            _,extensions=hello_fields(wire)
            shares=dict(extensions)[51]
            p=2;client_key=None
            while p<len(shares):
                group,n=struct.unpack('!HH',shares[p:p+4]);p+=4
                share=shares[p:p+n];p+=n
                if group==29:client_key=share
                elif group==4588 and n==1216:client_key=share[-32:]
            if client_key is None or len(client_key)!=32:raise ValueError('X25519 key share absent')
            shared=self.private.exchange(x25519.X25519PublicKey.from_public_bytes(client_key))
            auth=HKDF(hashes.SHA256(),32,random_bytes[:20],b'REALITY').derive(shared)
            aad=hello[:39]+bytes(32)+hello[71:]
            payload=AESGCM(auth).decrypt(random_bytes[20:],hello[39:71],aad)
            if payload[3]!=0 or abs(int.from_bytes(payload[4:8],'big')-time.time())>30 or payload[8:]!=bytes.fromhex('a1b2c3d4')+bytes(4):raise ValueError('REALITY timestamp/short id')
            self.authenticated+=1
            key=ed25519.Ed25519PrivateKey.generate()
            name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
            now=datetime.datetime.now(datetime.timezone.utc)
            cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                  .serial_number(42).not_valid_before(now-datetime.timedelta(minutes=1))
                  .not_valid_after(now+datetime.timedelta(hours=1))
                  .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False).sign(key,None))
            der=cert.public_bytes(serialization.Encoding.DER)
            self.assert_signature_length(cert,der)
            if not self.ordinary:
                mac=hmac.new(auth,key.public_key().public_bytes_raw(),hashlib.sha512).digest()
                if self.corrupt_auth:mac=bytes([mac[0]^1])+mac[1:]
                der=der[:-64]+mac
            exact(raw,5+size)
            certificate=der
            if self.signer:
                def certificate(client_hello,server_hello):
                    public=key.public_key().public_bytes_raw()
                    digest=hmac.new(auth,public+client_hello+server_hello,hashlib.sha512).digest()
                    self.signer.stdin.write(base64.b64encode(digest).decode()+'\n');self.signer.stdin.flush()
                    signature=base64.b64decode(self.signer.stdout.readline())
                    if self.bad_pq:signature=bytes([signature[0]^1])+signature[1:]
                    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                        .serial_number(42).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
                        .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.6.1.4.1.55555.1'),signature),False)
                        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False).sign(key,None))
                    return cert.public_bytes(serialization.Encoding.DER)[:-64]+hmac.new(auth,public,hashlib.sha512).digest()
            sock=TLS13Peer(raw,hello,shares,certificate,key,self.bad_verify,self.bad_finished)
            if exact(sock,18)!=b'\0'+old.ID.bytes+b'\0' or exact(sock,1)!=b'\1':raise ValueError('VLESS request')
            exact(sock,2);atyp=exact(sock,1)
            exact(sock,exact(sock,1)[0] if atyp==b'\2' else 4 if atyp==b'\1' else 16)
            sock.sendall(b'\0\0'+old.HELLO)
            while True:
                data=sock.recv(16384)
                if not data:break
                sock.sendall(data)
        except (EOFError,OSError,ssl.SSLError):pass
        except Exception as e:self.errors.append(type(e).__name__+': '+str(e))
        finally:sock.close();raw.close()

    @staticmethod
    def assert_signature_length(cert,der):
        if len(cert.signature)!=64 or der[-64:]!=cert.signature:raise ValueError('fixture certificate signature layout')

    def close(self):
        super().close()
        if self.signer:
            self.signer.terminate();self.signer.wait(3);self.signer.stdin.close();self.signer.stdout.close()


class RealityTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    socks=old.ExpandedTests.socks

    @staticmethod
    def uri(p,fp='chrome'):
        public=base64.urlsafe_b64encode(p.public).decode().rstrip('=')
        return f'vless://{old.ID}@127.0.0.1:{p.port}?security=reality&type=tcp&sni=localhost&fp={fp}&pbk={public}&sid=a1b2c3d4'

    def test_01_authenticated_profiles(self):
        for fp in ['chrome','firefox','safari','ios','edge','qq']:
            with self.subTest(fp=fp):
                p=RealityPeer()
                try:
                    with self.core(self.uri(p,fp)) as (port,log):
                        try:s=self.socks(port)
                        except Exception:time.sleep(.05);raise AssertionError(log.read_text()+repr(p.errors))
                        with s:
                            self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                            payload=random.Random(985).randbytes(210003)
                            with concurrent.futures.ThreadPoolExecutor() as pool:
                                send=pool.submit(s.sendall,payload)
                                self.assertEqual(hashlib.sha256(exact(s,len(payload))).digest(),hashlib.sha256(payload).digest());send.result(5)
                    self.assertEqual(p.authenticated,1);self.assertEqual(p.errors,[])
                finally:p.close()

    def test_02_wrong_authentication_and_ordinary_certificate(self):
        for ordinary in [False,True]:
            with self.subTest(ordinary=ordinary):
                p=RealityPeer(corrupt=True,ordinary=ordinary)
                try:
                    with self.core(self.uri(p)+'&allowInsecure=1') as (port,log):
                        s=socket.create_connection(('127.0.0.1',port),5);s.settimeout(8)
                        s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0')
                        s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(s,10)[1],0);s.close()
                    self.assertEqual(p.authenticated,1);self.assertEqual(p.errors,[])
                finally:p.close()

    def test_03_pq_signature_and_tls_transcript(self):
        for bad in ('','pq','verify','finished'):
            with self.subTest(bad=bad):
                p=RealityPeer(pq=True,bad_pq=bad=='pq',bad_verify=bad=='verify',bad_finished=bad=='finished')
                try:
                    with self.core(self.uri(p)+'&pqv='+p.pq_public+'&allowInsecure=1') as (port,log):
                        if not bad:
                            with self.socks(port) as s:
                                self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                                s.sendall(b'PQ verified');self.assertEqual(exact(s,11),b'PQ verified')
                        else:
                            with socket.create_connection(('127.0.0.1',port),5) as s:
                                s.settimeout(8);s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0')
                                s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(s,10)[1],0)
                    self.assertEqual(p.authenticated,1);self.assertEqual(p.errors,[])
                finally:p.close()

if __name__=='__main__':unittest.main(verbosity=2)
