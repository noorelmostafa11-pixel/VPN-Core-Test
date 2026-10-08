"""Independent crypto and SIP003 wire peers for additive support changes."""
import base64
import concurrent.futures
import hashlib
import os
import random
import socket
import ssl
import struct
import time
import unittest
from urllib.parse import quote
from Crypto.Cipher import ARC2, ARC4, Blowfish, CAST, DES, Salsa20, ChaCha20, ChaCha20_Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers import algorithms as legacy
import test_expanded as old
from test_core import exact

def master_key(size):
    result,prior=b'',b''
    while len(result)<size:
        prior=hashlib.md5(prior+old.SECRET.encode()).digest();result+=prior
    return result[:size]

def parameters(method):
    if method=='table':return 16,0
    if method=='rc4':return 16,0
    if method=='rc4-md5':return 16,16
    if method in ('salsa20','chacha20'):return 32,8
    if method=='chacha20-ietf':return 32,12
    if method=='des-cfb':return 8,8
    if method in ('bf-cfb','cast5-cfb','idea-cfb','rc2-cfb'):return 16,8
    if method=='seed-cfb':return 16,16
    return (16 if '-128-' in method else 24 if '-192-' in method else 32),16

def oracle(method,key,iv,decrypt=False):
    if method=='table':
        value=int.from_bytes(key[:8],'little');table=list(range(256))
        for n in range(1,1024):table=sorted(table,key=lambda x:value%(x+n))
        if decrypt:
            inverse=[0]*256
            for i,b in enumerate(table):inverse[b]=i
            table=inverse
        return lambda data:data.translate(bytes(table))
    if method.startswith('rc4'):
        if method=='rc4-md5':key=hashlib.md5(key+iv).digest()
        return ARC4.new(key).encrypt
    if method=='salsa20':return Salsa20.new(key=key,nonce=iv).encrypt
    if method in ('chacha20','chacha20-ietf'):return ChaCha20.new(key=key,nonce=iv).encrypt
    cls={'bf-cfb':Blowfish,'cast5-cfb':CAST,'des-cfb':DES,'rc2-cfb':ARC2}.get(method)
    if cls:
        options={'effective_keylen':128} if method=='rc2-cfb' else {}
        obj=cls.new(key,cls.MODE_CFB,iv=iv,segment_size=64,**options)
        return obj.decrypt if decrypt else obj.encrypt
    alg=legacy.IDEA(key) if method=='idea-cfb' else legacy.SEED(key) if method=='seed-cfb' else algorithms.Camellia(key)
    mode=modes.CFB(iv)
    obj=Cipher(alg,mode).decryptor() if decrypt else Cipher(alg,mode).encryptor()
    return obj.update

class StreamPeer(old.Peer):
    def __init__(self,method):super().__init__('ss',method)
    def handle(self,raw):
        try:
            raw.settimeout(10);size,niv=parameters(self.cipher);key=master_key(size)
            decode=oracle(self.cipher,key,exact(raw,niv),True);iv=os.urandom(niv);encode=oracle(self.cipher,key,iv)
            if decode(exact(raw,16))!=b'\3\x0cexample.test\1\xbb':raise ValueError('stream destination')
            # The IV and first payload cross unrelated TCP read boundaries.
            first=iv+encode(old.HELLO)
            for a,b in ((0,1),(1,3),(3,len(first))):raw.sendall(first[a:b])
            while True:
                encrypted=raw.recv(1103)
                if not encrypted:break
                raw.sendall(encode(decode(encrypted)))
        except (EOFError,OSError):pass
        except Exception as e:self.errors.append(repr(e))
        finally:raw.close()

class ObfsWire:
    def __init__(self,sock,mode):
        self.sock,self.mode,self.buffer,self.sent=sock,mode,bytearray(),False
        if mode=='http':
            request=bytearray()
            while not request.endswith(b'\r\n\r\n'):request+=exact(sock,1)
            lines=request.decode().split('\r\n')
            fields={p.split(':',1)[0].lower():p.split(':',1)[1].strip() for p in lines if ':' in p}
            if lines[0]!='GET /fixture HTTP/1.1' or fields['host']!='localhost':raise ValueError('obfs HTTP request')
        else:
            record=exact(sock,5);body=exact(sock,int.from_bytes(record[3:],'big'))
            if record[:3]!=b'\x16\3\1' or body[0]!=1:raise ValueError('obfs ClientHello')
            body=body[4:];pos=34;sid=body[pos];pos+=1+sid
            suites=int.from_bytes(body[pos:pos+2],'big');pos+=2+suites
            compression=body[pos];pos+=1+compression;pos+=2
            if body[pos:pos+2]!=b'\0\x23':raise ValueError('obfs session ticket')
            size=int.from_bytes(body[pos+2:pos+4],'big');self.buffer.extend(body[pos+4:pos+4+size])
    def settimeout(self,value):self.sock.settimeout(value)
    def close(self):self.sock.close()
    def recv(self,n):
        if self.mode=='http':return self.sock.recv(n)
        if not self.buffer:
            try:header=exact(self.sock,5)
            except EOFError:return b''
            if header[:3]!=b'\x17\3\3':raise ValueError('obfs application record')
            self.buffer.extend(exact(self.sock,int.from_bytes(header[3:],'big')))
        data=bytes(self.buffer[:n]);del self.buffer[:n];return data
    def sendall(self,data):
        if self.mode=='http':
            if not self.sent:data=b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'+data
        else:
            if not self.sent:
                ext=b'\xff\1\0\1\0\0\x17\0\0\0\x0b\0\2\1\0'
                body=b'\3\3'+os.urandom(32)+b'\x20'+os.urandom(32)+b'\xcc\xa8\0'+len(ext).to_bytes(2,'big')+ext
                hello=b'\2'+len(body).to_bytes(3,'big')+body
                data=b'\x16\3\1'+len(hello).to_bytes(2,'big')+hello+b'\x14\3\3\0\1\1'+b'\x16\3\3'+len(data).to_bytes(2,'big')+data
            else:data=b'\x17\3\3'+len(data).to_bytes(2,'big')+data
        self.sent=True
        # Split all three server handshake records and encrypted frames.
        self.sock.sendall(data[:3]);self.sock.sendall(data[3:7]);self.sock.sendall(data[7:])

class ObfsPeer(old.Peer):
    def __init__(self,mode):self.mode=mode;super().__init__('ss','aes-128-gcm')
    def handle(self,raw):
        try:super().handle(ObfsWire(raw,self.mode))
        except (EOFError,OSError):pass
        except Exception as e:self.errors.append(repr(e))
        finally:raw.close()

class XChaChaPeer(old.Peer):
    def __init__(self,bad=False):self.bad=bad;super().__init__('ss','xchacha20-ietf-poly1305')
    def handle(self,raw):
        try:
            raw.settimeout(10);key=master_key(32)
            def subkey(salt):
                import hmac
                prk=hmac.new(salt,key,'sha1').digest();a=hmac.new(prk,b'ss-subkey\1','sha1').digest()
                return (a+hmac.new(prk,a+b'ss-subkey\2','sha1').digest())[:32]
            upkey=subkey(exact(raw,32));salt=os.urandom(32);downkey=subkey(salt);up=down=0
            def decrypt(n):
                nonlocal up
                data=exact(raw,n+16);obj=ChaCha20_Poly1305.new(key=upkey,nonce=up.to_bytes(24,'little'));up+=1
                return obj.decrypt_and_verify(data[:-16],data[-16:])
            def encrypt(data):
                nonlocal down
                obj=ChaCha20_Poly1305.new(key=downkey,nonce=down.to_bytes(24,'little'));down+=1
                encrypted,tag=obj.encrypt_and_digest(data);return encrypted+tag
            size=int.from_bytes(decrypt(2),'big')
            if decrypt(size)!=b'\3\x0cexample.test\1\xbb':raise ValueError('XChaCha destination')
            response=salt+encrypt(len(old.HELLO).to_bytes(2,'big'))+encrypt(old.HELLO)
            if self.bad:response=response[:-1]+bytes([response[-1]^1])
            raw.sendall(response)
            if self.bad:return
            while True:
                n=int.from_bytes(decrypt(2),'big');data=decrypt(n)
                raw.sendall(encrypt(n.to_bytes(2,'big'))+encrypt(data))
        except (EOFError,OSError):pass
        except Exception as e:self.errors.append(repr(e))
        finally:raw.close()

class SupportAdditionTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core;socks=old.ExpandedTests.socks
    def exchange(self,peer,plugin=''):
        auth=base64.urlsafe_b64encode((peer.cipher+':'+old.SECRET).encode()).decode().rstrip('=')
        uri=f'ss://{auth}@127.0.0.1:{peer.port}?security=none'
        if plugin:uri+='&plugin='+quote(plugin,safe='')
        try:
            with self.core(uri) as (port,log):
                def run(seed):
                    with self.socks(port) as sock:
                        self.assertEqual(exact(sock,len(old.HELLO)),old.HELLO)
                        data=random.Random(seed).randbytes(65539);sock.sendall(data)
                        self.assertEqual(hashlib.sha256(exact(sock,len(data))).digest(),hashlib.sha256(data).digest())
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(run,range(2)))
                self.assertNotIn('failed phase=',log.read_text())
            self.assertEqual(peer.errors,[])
        finally:peer.close()
    def test_01_all_added_stream_ciphers(self):
        methods=['camellia-128-cfb','camellia-192-cfb','camellia-256-cfb','bf-cfb','cast5-cfb','des-cfb','idea-cfb','rc2-cfb','seed-cfb','rc4','rc4-md5','salsa20','chacha20','chacha20-ietf','table']
        for method in methods:
            with self.subTest(cipher=method):self.exchange(StreamPeer(method))
    def test_02_simple_obfs_modes_aliases(self):
        for name in ('obfs-local','simple-obfs'):
            for mode in ('http','tls'):
                with self.subTest(plugin=name,mode=mode):self.exchange(ObfsPeer(mode),f'{name};obfs={mode};obfs-host=localhost;obfs-uri=/fixture')
    def test_03_xchacha20_aead(self):self.exchange(XChaChaPeer())
    def test_04_xchacha20_rejects_bad_tag(self):
        peer=XChaChaPeer(bad=True);auth=base64.urlsafe_b64encode((peer.cipher+':'+old.SECRET).encode()).decode()
        try:
            with self.core(f'ss://{auth}@127.0.0.1:{peer.port}?security=none') as (port,log):
                with self.socks(port) as sock:
                    try:self.assertEqual(sock.recv(128),b'')
                    except ConnectionResetError:pass
                time.sleep(.03);self.assertIn('SS_RESPONSE_PAYLOAD_AUTH',log.read_text())
        finally:peer.close()

if __name__=='__main__':unittest.main(verbosity=2)
