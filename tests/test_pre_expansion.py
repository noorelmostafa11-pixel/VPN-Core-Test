"""Independent peers for formats found in the pinned Pre inventory."""
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import time
import unittest
from urllib.parse import quote
from blake3 import blake3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import test_expanded as old
from test_core import exact, ROOT

ADDRESS=b'\3\x0cexample.test\x01\xbb'

class SSPeer(old.Peer):
    def __init__(self,cipher,tls_context=None,identities=0,bad=''):
        self.identities=identities;self.bad=bad
        self.size=16 if '128' in cipher else 32
        self.keys=[hashlib.sha256(f'synthetic-test-key-{i}'.encode()).digest()[:self.size] for i in range(identities+1)]
        super().__init__('ss',cipher,'raw',tls_context)
    def handle(self,raw):
        sock=raw
        try:
            raw.settimeout(10)
            if self.tls_context:sock=self.tls_context.wrap_socket(raw,server_side=True)
            if self.cipher=='none' or self.cipher.startswith('aes-') and self.cipher.endswith(('cfb','ctr','ofb')):
                if self.cipher=='none':
                    read=lambda n:exact(sock,n);write=sock.sendall
                else:
                    size=16 if '128' in self.cipher else 24 if '192' in self.cipher else 32;master=b'';last=b''
                    while len(master)<size:last=hashlib.md5(last+old.SECRET.encode()).digest();master+=last
                    master=master[:size];decoder=Cipher(algorithms.AES(master),getattr(modes,self.cipher[-3:].upper())(exact(sock,16))).decryptor()
                    iv=os.urandom(16);encoder=Cipher(algorithms.AES(master),getattr(modes,self.cipher[-3:].upper())(iv)).encryptor();sock.sendall(iv)
                    read=lambda n:decoder.update(exact(sock,n));write=lambda b:sock.sendall(encoder.update(b))
                if read(len(ADDRESS))!=ADDRESS:raise ValueError('legacy SS address')
                write(old.HELLO)
                while True:
                    data=sock.recv(1001)
                    if not data:break
                    if self.cipher!='none':data=decoder.update(data)
                    write(data)
                return
            salt=exact(sock,self.size)
            for i in range(self.identities):
                key=blake3(self.keys[i]+salt,derive_key_context='shadowsocks 2022 identity subkey').digest()[:self.size]
                block=Cipher(algorithms.AES(key),modes.ECB()).decryptor().update(exact(sock,16))
                if block!=blake3(self.keys[i+1]).digest()[:16]:raise ValueError('identity hash')
            def key(s):return blake3(self.keys[-1]+s,derive_key_context='shadowsocks 2022 session subkey').digest()[:self.size]
            constructor=ChaCha20Poly1305 if 'chacha' in self.cipher else AESGCM
            decoder=constructor(key(salt));up=0;down=0
            def decrypt(n):
                nonlocal up
                data=decoder.decrypt(up.to_bytes(12,'little'),exact(sock,n+16),None);up+=1;return data
            fixed=decrypt(11)
            if fixed[0]!=0 or abs(time.time()-int.from_bytes(fixed[1:9],'big'))>30:raise ValueError('request timestamp/type')
            variable=decrypt(int.from_bytes(fixed[9:],'big'))
            if variable[:len(ADDRESS)]!=ADDRESS:raise ValueError('SS2022 address')
            padding=int.from_bytes(variable[len(ADDRESS):len(ADDRESS)+2],'big')
            if not 1<=padding<=900 or len(variable)!=len(ADDRESS)+2+padding:raise ValueError('SS2022 padding')
            response_salt=os.urandom(self.size);encoder=constructor(key(response_salt))
            timestamp=int(time.time())-(100 if self.bad=='timestamp' else 0)
            reflected=(bytes(self.size) if self.bad=='request_salt' else salt)
            header=b'\1'+timestamp.to_bytes(8,'big')+reflected+len(old.HELLO).to_bytes(2,'big')
            encrypted=encoder.encrypt(bytes(12),header,None);down=1
            if self.bad=='tag':encrypted=encrypted[:-1]+bytes([encrypted[-1]^1])
            sock.sendall(response_salt+encrypted)
            def send(data):
                nonlocal down
                result=encoder.encrypt(down.to_bytes(12,'little'),data,None);down+=1;return result
            sock.sendall(send(old.HELLO))
            if self.bad:return
            while True:
                size=int.from_bytes(decrypt(2),'big');data=decrypt(size)
                if not data:break
                sock.sendall(send(len(data).to_bytes(2,'big'))+send(data))
        except (EOFError,OSError,ssl.SSLError):pass
        except Exception as e:self.errors.append(repr(e))
        finally:sock.close();raw.close()

class VMessPeer(old.Peer):
    def __init__(self,cipher,aid=0,tls_context=None,bad=False):
        self.aid=aid;self.bad=bad
        super().__init__('vmess',cipher,'raw',tls_context)
    def handle(self,raw):
        sock=raw
        try:
            raw.settimeout(10)
            if self.tls_context:sock=self.tls_context.wrap_socket(raw,server_side=True)
            auth=exact(sock,16);command=hashlib.md5(old.ID.bytes+b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()
            if self.aid:
                ids=[];prior=old.ID.bytes
                for i in range(self.aid):prior=hashlib.md5(prior+b'16167dc8-16b6-4e6d-b8bb-65dd68113a81').digest();ids.append(prior)
                timestamp=None
                for t in range(int(time.time())-30,int(time.time())+31):
                    if any(hmac.new(i,t.to_bytes(8,'big'),'md5').digest()==auth for i in ids):timestamp=t;break
                if timestamp is None:raise ValueError('legacy authentication')
                iv=hashlib.md5(timestamp.to_bytes(8,'big')*4).digest();decoder=Cipher(algorithms.AES(command),modes.CFB(iv)).decryptor()
                header=decoder.update(exact(sock,42));header+=decoder.update(exact(sock,header[41]+(header[35]>>4)+4))
            else:
                length,nonce=exact(sock,18),exact(sock,8)
                def k(label,n):return old.kdf(command,label,auth,nonce)[:n]
                length=int.from_bytes(AESGCM(k(b'VMess Header AEAD Key_Length',16)).decrypt(k(b'VMess Header AEAD Nonce_Length',12),length,auth),'big')
                header=AESGCM(k(b'VMess Header AEAD Key',16)).decrypt(k(b'VMess Header AEAD Nonce',12),exact(sock,length+16),auth)
            if old.fnv(header[:-4])!=int.from_bytes(header[-4:],'big') or header[0]!=1:raise ValueError('header checksum')
            expected=1 if self.cipher=='aes-128-cfb' else 5 if self.cipher in ('zero','none') else 4 if 'chacha' in self.cipher else 3
            if header[35]&15!=expected or header[34]!=(0 if self.cipher=='zero' else 1) or header[37:42]!=b'\1\1\xbb\2\x0c':raise ValueError('options/cipher/address')
            up_iv,up_key,v=header[1:17],header[17:33],header[33]
            hash_fn=hashlib.md5 if self.aid else hashlib.sha256
            down_iv,down_key=hash_fn(up_iv).digest()[:16],hash_fn(up_key).digest()[:16]
            resp=bytes([v^1 if self.bad else v,0,0,0])
            response_encoder=Cipher(algorithms.AES(down_key),modes.CFB(down_iv)).encryptor()
            if self.aid:sock.sendall(response_encoder.update(resp))
            else:sock.sendall(AESGCM(old.kdf(down_key,b'AEAD Resp Header Len Key')[:16]).encrypt(old.kdf(down_iv,b'AEAD Resp Header Len IV')[:12],b'\0\4',None)+AESGCM(old.kdf(down_key,b'AEAD Resp Header Key')[:16]).encrypt(old.kdf(down_iv,b'AEAD Resp Header IV')[:12],resp,None))
            if self.bad:return
            if self.cipher=='zero':
                read=lambda:sock.recv(1001);write=sock.sendall
            elif self.cipher=='aes-128-cfb':
                dec=Cipher(algorithms.AES(up_key),modes.CFB(up_iv)).decryptor()
                enc=response_encoder if self.aid else Cipher(algorithms.AES(down_key),modes.CFB(down_iv)).encryptor()
                def read():
                    size=int.from_bytes(dec.update(exact(sock,2)),'big');body=dec.update(exact(sock,size));data=body[4:]
                    if old.fnv(data)!=int.from_bytes(body[:4],'big'):raise ValueError('CFB chunk checksum')
                    return data
                def write(data):
                    body=old.fnv(data).to_bytes(4,'big')+data;sock.sendall(enc.update(len(body).to_bytes(2,'big')+body))
            else:
                def expand(k):a=hashlib.md5(k).digest();return a+hashlib.md5(a).digest()
                cons=ChaCha20Poly1305 if 'chacha' in self.cipher else AESGCM
                decoder=cons(expand(up_key) if 'chacha' in self.cipher else up_key);encoder=cons(expand(down_key) if 'chacha' in self.cipher else down_key);counts=[0,0]
                def read():
                    size=int.from_bytes(exact(sock,2),'big');body=exact(sock,size);nonce=counts[0].to_bytes(2,'big')+up_iv[2:12];counts[0]+=1;return body if self.cipher=='none' else decoder.decrypt(nonce,body,None)
                def write(data):
                    nonce=counts[1].to_bytes(2,'big')+down_iv[2:12];counts[1]+=1;body=data if self.cipher=='none' else encoder.encrypt(nonce,data,None);sock.sendall(len(body).to_bytes(2,'big')+body)
            write(old.HELLO)
            while True:
                data=read()
                if not data:break
                write(data)
        except (EOFError,OSError,ssl.SSLError):pass
        except Exception as e:self.errors.append(repr(e))
        finally:sock.close();raw.close()

class PreExpansionTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    socks=old.ExpandedTests.socks
    def uri(self,p):
        password=':'.join(base64.b64encode(k).decode() for k in p.keys) if p.cipher.startswith('2022') else old.SECRET
        auth=quote(p.cipher+':'+password,safe='')
        return f'ss://{auth}@127.0.0.1:{p.port}?security={"tls" if p.tls_context else "none"}&sni=localhost'
    def exchange(self,cipher,identities=0,tls=False):
        p=SSPeer(cipher,self.context if tls else None,identities)
        try:
            with self.core(self.uri(p)) as (port,_):
                with self.socks(port) as s:
                    self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                    data=random.Random(448).randbytes(280000)
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        future=pool.submit(s.sendall,data);self.assertEqual(hashlib.sha256(exact(s,len(data))).digest(),hashlib.sha256(data).digest());future.result(10)
            self.assertEqual(p.errors,[])
        finally:p.close()
    def test_01_blake3_differential(self):
        rng=random.Random(89);rows=[];expected=[]
        for size in [0,1,31,32,63,64,65,127,128,511,512,513,1023,1024]:
            material=rng.randbytes(size);rows.append('blake3 '+(material.hex() or '-'));expected.append(blake3(material).hexdigest())
            context=b'shadowsocks 2022 session subkey';rows.append('blake3-derive '+context.hex()+' '+(material.hex() or '-'));expected.append(blake3(material,derive_key_context=context.decode()).hexdigest())
        r=subprocess.run([str(ROOT/'bin/crypto-probe')],input='\n'.join(rows)+'\n',text=True,capture_output=True,check=True)
        self.assertEqual(r.stdout.splitlines(),expected)
    def test_02_ss2022_aes128(self):self.exchange('2022-blake3-aes-128-gcm')
    def test_03_ss2022_aes256(self):self.exchange('2022-blake3-aes-256-gcm')
    def test_04_ss2022_chacha(self):self.exchange('2022-blake3-chacha20-poly1305')
    def test_05_ss2022_identity_chain(self):self.exchange('2022-blake3-aes-256-gcm',identities=2)
    def test_06_ss2022_verified_tls(self):self.exchange('2022-blake3-aes-128-gcm',tls=True)
    def test_07_aes_cfb128(self):self.exchange('aes-128-cfb',tls=True)
    def test_08_aes_cfb256(self):self.exchange('aes-256-cfb',tls=True)
    def test_16_aes192_and_stream_modes(self):
        for cipher in ('aes-192-cfb','aes-128-ctr','aes-192-ctr','aes-256-ctr','aes-128-ofb','aes-192-ofb','aes-256-ofb'):
            with self.subTest(cipher=cipher):self.exchange(cipher,tls=True)
    def test_09_plain_inside_verified_tls(self):self.exchange('none',tls=True)
    def test_10_ss2022_reject_bad_response(self):
        for bad in ['timestamp','request_salt','tag']:
            with self.subTest(bad=bad):
                p=SSPeer('2022-blake3-aes-256-gcm',bad=bad)
                try:
                    with self.core(self.uri(p)) as (port,log):
                        with self.socks(port) as s:self.assertEqual(s.recv(100),b'')
                        deadline=time.monotonic()+2
                        while 'PROTOCOL_FAILED' not in log.read_text() and time.monotonic()<deadline:time.sleep(.01)
                        self.assertIn('PROTOCOL_FAILED',log.read_text())
                finally:p.close()
    def vmess_exchange(self,cipher,aid):
        p=VMessPeer(cipher,aid,self.context)
        try:
            uri=old.ExpandedTests.uri(self,p)+'&aid='+str(aid)
            with self.core(uri) as (port,_):
                with self.socks(port) as s:
                    self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                    data=random.Random(759).randbytes(150013)
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        future=pool.submit(s.sendall,data);self.assertEqual(exact(s,len(data)),data);future.result(10)
            self.assertEqual(p.errors,[])
        finally:p.close()
    def test_11_vmess_legacy_gcm(self):
        for aid in [1,2,16,32,64,233]:
            with self.subTest(aid=aid):self.vmess_exchange('aes-128-gcm',aid)
    def test_12_vmess_legacy_chacha(self):self.vmess_exchange('chacha20-poly1305',64)
    def test_13_vmess_legacy_none(self):self.vmess_exchange('none',1)
    def test_14_vmess_zero(self):
        for aid in [0,64]:
            with self.subTest(aid=aid):self.vmess_exchange('zero',aid)
    def test_15_vmess_cfb(self):
        for aid in [0,64]:
            with self.subTest(aid=aid):self.vmess_exchange('aes-128-cfb',aid)

if __name__=='__main__':unittest.main(verbosity=2)
