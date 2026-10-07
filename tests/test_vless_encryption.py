"""Hybrid key exchange, native/random records, tickets and tampering."""
import concurrent.futures
import contextlib
import hashlib
import json
import pathlib
import random
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.parse import quote
import test_expanded as old
from test_core import exact,ROOT

class VlessEncryptionTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    socks=old.ExpandedTests.socks
    @contextlib.contextmanager
    def peer(self,mode='native',relays=1,kem=False,bad='',tls=False,crypto=None):
        crypto=crypto or old.Peer('vless')
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            logpath=pathlib.Path(directory)/'peer.log'
            with logpath.open('w') as log:
                args=[str(ROOT/'bin/vless-encryption-peer'),'-target',f'127.0.0.1:{crypto.port}','-mode',mode,'-relays',str(relays),'-bad',bad]
                if kem:args+=['-kem']
                if tls:args+=['-cert',str(old.original.CoreTests.cert),'-key',str(old.original.CoreTests.key)]
                process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=log,text=True)
                try:
                    info=json.loads(process.stdout.readline());yield info,crypto,logpath
                finally:process.terminate();process.wait(3);process.stdout.close();crypto.close()
    def uri(self,info,mode,rtt,tls=False,padding=''):
        encryption='.'.join(['mlkem768x25519plus',mode,rtt]+([padding] if padding else [])+info['keys'])
        return f'vless://{old.ID}@127.0.0.1:{info["port"]}?encryption='+quote(encryption,safe='')+f'&security={"tls" if tls else "none"}&sni=localhost&fp=chrome'
    def exchange(self,mode='native',rtt='1rtt',relays=1,kem=False,tls=False,padding='',connections=2):
        with self.peer(mode,relays,kem,tls=tls) as (info,crypto,peer_log):
            with self.core(self.uri(info,mode,rtt,tls,padding)) as (port,core_log):
                def run(seed):
                    with self.socks(port) as s:
                        self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                        data=random.Random(seed).randbytes(310007);s.sendall(data)
                        self.assertEqual(hashlib.sha256(exact(s,len(data))).digest(),hashlib.sha256(data).digest())
                run(0)
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(run,range(1,connections)))
                self.assertNotIn('failed phase=',core_log.read_text())
            self.assertEqual(crypto.errors,[])
            lines=peer_log.read_text().splitlines()
            if rtt=='0rtt':self.assertGreaterEqual(lines.count('RESUMED'),connections-1)
            self.assertFalse(any(line.startswith('VALIDATION:') for line in lines),lines)
    def test_01_native_and_random_one_rtt(self):
        for mode in ('native','xorpub','random'):
            with self.subTest(mode=mode):self.exchange(mode)
    def test_02_zero_rtt_parallel(self):
        for mode in ('native','random'):
            with self.subTest(mode=mode):self.exchange(mode,'0rtt',connections=8)
    def test_03_relay_chains_and_static_kem(self):
        for mode,relays,kem in [('native',2,False),('random',3,False),('native',1,True),('random',2,True)]:
            with self.subTest(mode=mode,relays=relays,kem=kem):self.exchange(mode,relays=relays,kem=kem)
    def test_04_configured_handshake_padding(self):
        self.exchange('random',padding='100-75-100.100-0-1.50-0-15')
    def test_05_verified_tls_wrapper(self):
        self.exchange('native','0rtt',tls=True,connections=3)
    def test_06_authenticated_messages_and_lengths(self):
        for bad in ('handshake_tag','ticket_tag','padding_tag','record_tag','record_length'):
            with self.subTest(bad=bad),self.peer(bad=bad) as (info,crypto,peer_log):
                with self.core(self.uri(info,'native','1rtt')) as (port,log):
                    with self.socks(port) as s:
                        try:self.assertEqual(s.recv(100),b'')
                        except ConnectionResetError:pass
                    time.sleep(.05);self.assertIn('VLESS_ENCRYPTION_AUTHENTICATION',log.read_text())

    def test_07_encryption_with_vision(self):
        import test_vision
        for mode in ('native','random'):
            crypto=test_vision.VisionPeer(self.context,plain=True)
            with self.subTest(mode=mode),self.peer(mode,tls=True,crypto=crypto) as (info,crypto,peer_log):
                with self.core(self.uri(info,mode,'0rtt',tls=True)+'&flow=xtls-rprx-vision') as (port,log):
                    def run(seed):
                        with self.socks(port) as s:
                            self.assertEqual(exact(s,len(old.HELLO)+4),old.HELLO+b'tail')
                            data=random.Random(seed).randbytes(120009);s.sendall(data)
                            self.assertEqual(hashlib.sha256(exact(s,len(data))).digest(),hashlib.sha256(data).digest())
                    run(0)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(run,range(1,4)))
                    self.assertNotIn('failed phase=',log.read_text())
                self.assertEqual(crypto.errors,[])

    def test_08_encryption_with_xhttp(self):
        import test_xhttp_modes
        for mode in ('packet-up','stream-up','stream-one'):
            with self.subTest(mode=mode),self.peer('random') as (info,crypto,peer_log):
                extra={'_target':f'127.0.0.1:{info["port"]}'}
                with test_xhttp_modes.XHttpTests.peer(self,'vless','',mode,tls=True,h2=True,extra=extra) as (uri,unused,http_log):
                    encryption=quote('.'.join(['mlkem768x25519plus','random','0rtt']+info['keys']),safe='')
                    with self.core(uri+'&fp=chrome&encryption='+encryption) as (port,log):
                        def run(seed):
                            with self.socks(port) as s:
                                self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                                data=random.Random(seed).randbytes(120019);s.sendall(data)
                                try:received=exact(s,len(data))
                                except Exception as e:
                                    time.sleep(.05);raise AssertionError(log.read_text()+'\nEN:'+peer_log.read_text()+'\nHTTP:'+http_log.read_text()+'\ncrypto:'+repr(crypto.errors)) from e
                                self.assertEqual(hashlib.sha256(received).digest(),hashlib.sha256(data).digest())
                        run(0)
                        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(run,range(1,4)))
                        self.assertNotIn('failed phase=',log.read_text())
                    self.assertEqual(http_log.read_text(),'')
                self.assertEqual(crypto.errors,[])

if __name__=='__main__':unittest.main(verbosity=2)
