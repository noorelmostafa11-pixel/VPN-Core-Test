"""Exercise the embedded TLS provider against Python/OpenSSL TLS servers."""
import concurrent.futures
import hashlib
import base64
import random
import socket
import ssl
import struct
import time
import unittest
from urllib.parse import quote
import test_expanded as old
from test_core import exact

def hello_fields(wire):
    if wire[:1]!=b'\x16' or wire[5:6]!=b'\x01':raise ValueError('ClientHello framing')
    body=wire[9:];p=34;size=body[p];p+=1+size;n=int.from_bytes(body[p:p+2],'big');p+=2
    ciphers=[int.from_bytes(body[x:x+2],'big') for x in range(p,p+n,2)];p+=n;n=body[p];p+=1+n
    n=int.from_bytes(body[p:p+2],'big');p+=2;end=p+n;extensions=[]
    while p<end:
        kind,length=struct.unpack('!HH',body[p:p+4]);p+=4
        if p+length>end:raise ValueError('ClientHello extension length')
        extensions.append((kind,body[p:p+length]));p+=length
    return ciphers,extensions

class CapturePeer(old.Peer):
    def __init__(self,*args,**kwargs):self.hellos=[];super().__init__(*args,**kwargs)
    def handle(self,raw):
        raw.settimeout(10)
        try:
            until=time.monotonic()+5
            while time.monotonic()<until:
                wire=raw.recv(65536,socket.MSG_PEEK)
                if len(wire)>=5 and len(wire)>=5+int.from_bytes(wire[3:5],'big'):break
                time.sleep(.001)
            self.hellos.append(hello_fields(wire))
        except Exception as e:self.errors.append(repr(e))
        super().handle(raw)

class TLSProfileTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    uri=old.ExpandedTests.uri
    socks=old.ExpandedTests.socks
    def exchange(self,fp,transport='raw',protocol='vless',tls12=False,alpn=''):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key);context.minimum_version=ssl.TLSVersion.TLSv1_2
        if tls12:context.maximum_version=ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['h2','http/1.1'])
        p=CapturePeer(protocol,'aes-128-gcm' if protocol=='vmess' else '',transport,context)
        try:
            uri=self.uri(p)+'&fp='+fp
            if alpn:uri+='&alpn='+quote(alpn,safe='')
            with self.core(uri) as (port,log):
                try:s=self.socks(port)
                except Exception:
                    time.sleep(.1);raise AssertionError(log.read_text())
                with s:
                    self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                    data=random.Random(894).randbytes(120003)
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        future=pool.submit(s.sendall,data);self.assertEqual(hashlib.sha256(exact(s,len(data))).digest(),hashlib.sha256(data).digest());future.result(10)
                if tls12:self.assertIn('TLS1.2',log.read_text())
            self.assertEqual(p.errors,[]);self.assertEqual(len(p.hellos),1)
            ciphers,extensions=p.hellos[0];self.assertGreater(len(ciphers),5);self.assertIn(0,[k for k,_ in extensions])
            # Profile advertises certificate compression, then provider must
            # have its matching decoder. This also distinguishes native TLS.
            if fp=='chrome':self.assertIn(27,[k for k,_ in extensions])
            if fp=='randomizednoalpn':self.assertNotIn(16,[k for k,_ in extensions])
        finally:p.close()
    def test_01_all_inventory_profiles(self):
        for fp in ['chrome','firefox','safari','ios','android','edge','360','qq','random','randomized']:
            with self.subTest(fp=fp):self.exchange(fp)
    def test_02_tls12_profiles(self):
        for fp in ['chrome','firefox','safari','edge','360','qq']:
            with self.subTest(fp=fp):self.exchange(fp,tls12=True)
    def test_03_vmess_profile(self):self.exchange('chrome',protocol='vmess')
    def test_04_trojan_profile(self):self.exchange('firefox',protocol='trojan')
    def test_05_websocket_alpn(self):self.exchange('chrome',transport='websocket')
    def test_06_grpc_alpn(self):self.exchange('chrome',transport='grpc')
    def test_09_randomized_without_alpn(self):
        self.exchange('randomizednoalpn')
        self.exchange('randomizednoalpn',tls12=True)
    def test_10_randomized_without_alpn_websocket_parallel(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _:self.exchange('randomizednoalpn',transport='websocket',alpn='h3,h2,http/1.1'),range(8)))
    def test_11_randomized_without_alpn_wrong_certificate(self):
        self.test_07_wrong_name_rejected(fp='randomizednoalpn')
    def test_07_wrong_name_rejected(self,fp='chrome'):
        p=old.Peer('vless',tls_context=self.context)
        try:
            uri=self.uri(p).replace('sni=localhost','sni=wrong.invalid')+'&fp='+fp+'&allowInsecure=1'
            with self.core(uri) as (port,log):
                s=socket.create_connection(('127.0.0.1',port),5);s.settimeout(8);s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0');s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(s,10)[1],0);s.close()
                deadline=time.monotonic()+2
                while 'TLS_CERTIFICATE_NAME' not in log.read_text() and time.monotonic()<deadline:time.sleep(.01)
                self.assertIn('TLS_CERTIFICATE_NAME',log.read_text())
        finally:p.close()

    def test_08_certificate_pins_and_verification_names(self):
        der=ssl.PEM_cert_to_DER_cert(old.original.CoreTests.cert.read_text())
        pin=hashlib.sha256(der).digest()
        for pins,names,success in [(pin.hex(),'localhost',True),('sha256/'+base64.b64encode(pin).decode(),'localhost',True),('00'*32,'localhost',False),(pin.hex(),'wrong.invalid',False)]:
            with self.subTest(success=success,names=names):
                p=old.Peer('vless',tls_context=self.context)
                try:
                    uri=self.uri(p)+'&pcs='+quote(pins,safe='')+'&vcn='+quote(names,safe='')+'&allowInsecure=1'
                    with self.core(uri) as (port,log):
                        if success:
                            with self.socks(port) as s:self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                        else:
                            s=socket.create_connection(('127.0.0.1',port),5);s.settimeout(8);s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0');s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(s,10)[1],0);s.close()
                finally:p.close()

if __name__=='__main__':unittest.main(verbosity=2)
