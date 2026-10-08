"""Legacy QUIC and SIP003 QUIC with independently verified inner protocols."""
import base64
import contextlib
import hashlib
import json
import pathlib
import random
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from urllib.parse import quote
import test_expanded as old
from test_core import exact,ROOT

class QUICCarrierTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core;socks=old.ExpandedTests.socks
    @contextlib.contextmanager
    def peer(self,protocol='vless',cipher='',outer='none',header='none',plugin=False,cert_raw='',cert_path='',legacy=False):
        crypto=old.Peer(protocol,cipher)
        with tempfile.TemporaryDirectory(dir=self.directory) as td:
            root=pathlib.Path(td);cfg=root/'peer.json';cfg.write_text(json.dumps(dict(Target=f'127.0.0.1:{crypto.port}',Cert=str(old.original.CoreTests.cert),Key=str(old.original.CoreTests.key),Cipher=outer,Secret='fixture-quic-key',Header=header)))
            log=(root/'peer.log').open('w');process=subprocess.Popen([str(ROOT/'bin/quic-peer'),'-config',str(cfg)],stdout=subprocess.PIPE,stderr=log,text=True)
            try:
                port=process.stdout.readline().strip().rsplit(':',1)[1]
                auth=str(old.ID) if protocol in ('vless','vmess') else quote(old.SECRET,safe='')
                if protocol=='ss':auth=base64.urlsafe_b64encode((cipher+':'+old.SECRET).encode()).decode().rstrip('=')
                uri=f'{protocol}://{auth}@127.0.0.1:{port}?type=quic&security=tls&sni=localhost&quicsecurity={outer}&quickey=fixture-quic-key&headerType={header}'
                if protocol=='vmess':uri+='&encryption='+cipher
                if plugin:
                    options='v2ray-plugin;mode=quic;host=localhost;mux=8'
                    if cert_raw:options+=';certRaw='+cert_raw
                    if cert_path:options+=';cert='+str(cert_path)
                    uri+='&plugin='+quote(options,safe='')
                if legacy:
                    node={'v':'2','add':'127.0.0.1','port':port,'id':str(old.ID),'aid':'0','scy':cipher,'net':'quic','tls':'tls','sni':'localhost','host':outer,'path':'fixture-quic-key','type':header}
                    uri='vmess://'+base64.b64encode(json.dumps(node).encode()).decode()
                yield uri,crypto,root/'peer.log'
            finally:
                process.terminate();process.wait(5);process.stdout.close();log.close();crypto.close()
    def exchange(self,**options):
        for fp in ('native','chrome','firefox'):
            with self.peer(**options) as (uri,crypto,peer_log):
                if options.get('legacy'):
                    node=json.loads(base64.b64decode(uri.split('://',1)[1]));node['fp']=fp
                    uri='vmess://'+base64.b64encode(json.dumps(node).encode()).decode()
                else:uri+='&fp='+fp
                with self.core(uri) as (port,log):
                    with self.socks(port) as sock:
                        self.assertEqual(exact(sock,len(old.HELLO)),old.HELLO)
                        data=random.Random(42).randbytes(100019);sock.sendall(data)
                        self.assertEqual(hashlib.sha256(exact(sock,len(data))).digest(),hashlib.sha256(data).digest())
                    self.assertEqual(crypto.errors,[]);self.assertNotIn('failed phase=',log.read_text())
    def test_01_four_protocols(self):
        for protocol,cipher in [('vless',''),('vmess','aes-128-gcm'),('trojan',''),('ss','chacha20-ietf-poly1305')]:
            with self.subTest(protocol=protocol):self.exchange(protocol=protocol,cipher=cipher)
    def test_02_packet_protection_and_header(self):
        for outer in ('aes-128-gcm','chacha20-poly1305'):
            with self.subTest(outer=outer):self.exchange(outer=outer,header='srtp')
    def test_03_plugin_quic(self):self.exchange(protocol='ss',cipher='aes-128-gcm',plugin=True)
    def test_07_legacy_vmess_quic_fields(self):self.exchange(protocol='vmess',cipher='aes-128-gcm',outer='chacha20-poly1305',header='srtp',legacy=True)
    def test_04_plugin_certificate(self):
        der=ssl.PEM_cert_to_DER_cert(old.original.CoreTests.cert.read_text())
        self.exchange(protocol='ss',cipher='aes-128-gcm',plugin=True,cert_raw=base64.b64encode(der).decode())
    def test_05_wrong_server_name(self):
        with self.peer() as (uri,crypto,peer_log),self.core(uri.replace('sni=localhost','sni=wrong.example')) as (port,log):
            with socket.create_connection(('127.0.0.1',port),5) as sock:
                sock.settimeout(10);sock.sendall(b'\5\1\0');self.assertEqual(exact(sock,2),b'\5\0');sock.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(sock,10)[1],0)
            time.sleep(.03);self.assertIn('TLS_CERTIFICATE_NAME',log.read_text());self.assertEqual(crypto.accepted,0)
    def test_06_plugin_wrong_certificate(self):
        # A different independently generated certificate, not the issuing CA.
        bad=self.directory/'wrong.pem';key=self.directory/'wrong.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(bad),'-days','2','-subj','/CN=unrelated.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        wrong=base64.b64encode(ssl.PEM_cert_to_DER_cert(bad.read_text())).decode()
        with self.peer(protocol='ss',cipher='aes-128-gcm',plugin=True,cert_raw=wrong) as (uri,crypto,peer_log),self.core(uri) as (port,log):
            with socket.create_connection(('127.0.0.1',port),5) as sock:
                sock.settimeout(10);sock.sendall(b'\5\1\0');self.assertEqual(exact(sock,2),b'\5\0');sock.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(sock,10)[1],0)
            time.sleep(.03);self.assertIn('TLS_CERTIFICATE_',log.read_text());self.assertEqual(crypto.accepted,0)

    def test_08_plugin_file_certificate(self):
        # The official plugin gives cert precedence over certRaw.
        self.exchange(protocol='ss',cipher='aes-128-gcm',plugin=True,cert_path=old.original.CoreTests.cert,cert_raw='invalid-and-overridden')

    def test_09_plugin_file_rejects_unrelated_certificate_even_with_other_roots(self):
        bad=self.directory/'unrelated-file.pem';key=self.directory/'unrelated-file.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(bad),'-days','2','-subj','/CN=unrelated.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        good=base64.b64encode(ssl.PEM_cert_to_DER_cert(old.original.CoreTests.cert.read_text())).decode()
        with self.peer(protocol='ss',cipher='aes-128-gcm',plugin=True,cert_path=bad,cert_raw=good) as (uri,crypto,peer_log),self.core(uri) as (port,log):
            with socket.create_connection(('127.0.0.1',port),5) as sock:
                sock.settimeout(10);sock.sendall(b'\5\1\0');self.assertEqual(exact(sock,2),b'\5\0');sock.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(sock,10)[1],0)
            time.sleep(.03);self.assertIn('TLS_CERTIFICATE_',log.read_text());self.assertEqual(crypto.accepted,0)

if __name__=='__main__':unittest.main(verbosity=2)
