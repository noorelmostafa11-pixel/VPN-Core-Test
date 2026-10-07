"""Small independent TLS 1.3 test server for REALITY's Ed25519 certificate.

REALITY uses Ed25519 CertificateVerify even for browser ClientHello templates
that omit Ed25519 from their advertised signature list. General-purpose TLS
servers reject that pairing, so this fixture implements and checks the TLS
1.3 handshake and record keys directly. It is not linked into the core.
"""
import hashlib
import hmac
import os
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_core import exact


def message(kind,body):return bytes([kind])+len(body).to_bytes(3,'big')+body
def extract(salt,secret):return hmac.new(salt,secret,hashlib.sha256).digest()
def expand(secret,label,context,n):
    label=b'tls13 '+label
    info=struct.pack('!H',n)+bytes([len(label)])+label+bytes([len(context)])+context
    out=b'';previous=b'';counter=1
    while len(out)<n:
        previous=extract(secret,previous+info+bytes([counter]));out+=previous;counter+=1
    return out[:n]
def derive(secret,label,transcript):return expand(secret,label,hashlib.sha256(transcript).digest(),32)


class RecordKeys:
    def __init__(self,secret):
        self.aead=AESGCM(expand(secret,b'key',b'',16))
        self.iv=expand(secret,b'iv',b'',12);self.sequence=0
    def nonce(self):
        counter=self.sequence.to_bytes(12,'big');self.sequence+=1
        return bytes(a^b for a,b in zip(self.iv,counter))
    def encrypt(self,kind,data):
        plain=data+bytes([kind]);head=b'\x17\3\3'+struct.pack('!H',len(plain)+16)
        return head+self.aead.encrypt(self.nonce(),plain,head)
    def decrypt(self,head,data):
        plain=self.aead.decrypt(self.nonce(),data,head).rstrip(b'\0')
        if not plain:raise ValueError('TLS inner content type absent')
        return plain[-1],plain[:-1]


class TLS13Peer:
    def __init__(self,sock,hello,shares,certificate,key,corrupt_verify=False,corrupt_finished=False):
        self.socket=sock;self.buffer=bytearray();self.ended=False
        # Use an offered classical share so the fixture requires no second
        # implementation of ML-KEM. The REALITY authentication can still use
        # the hybrid share's X25519 public key.
        client=None;p=2
        while p<len(shares):
            group,n=struct.unpack('!HH',shares[p:p+4]);p+=4
            share=shares[p:p+n];p+=n
            if group==29:client=share
        if client is None:raise ValueError('fixture requires offered X25519 share')
        private=x25519.X25519PrivateKey.generate()
        shared=private.exchange(x25519.X25519PublicKey.from_public_bytes(client))
        extension=b'\0+\0\2\3\4'+b'\0\x33\0\x24\0\x1d\0\x20'+private.public_key().public_bytes_raw()
        sh=message(2,b'\3\3'+os.urandom(32)+b'\x20'+hello[39:71]+b'\x13\1\0'+struct.pack('!H',len(extension))+extension)
        if callable(certificate):certificate=certificate(hello,sh)
        sock.sendall(b'\x16\3\3'+struct.pack('!H',len(sh))+sh)
        early=extract(bytes(32),bytes(32))
        secret=extract(derive(early,b'derived',b''),shared)
        transcript=hello+sh
        client_hs=derive(secret,b'c hs traffic',transcript)
        server_hs=derive(secret,b's hs traffic',transcript)
        client_records=RecordKeys(client_hs);server_records=RecordKeys(server_hs)
        ee=message(8,b'\0\0')
        cert_entry=len(certificate).to_bytes(3,'big')+certificate+b'\0\0'
        cert=message(11,b'\0'+len(cert_entry).to_bytes(3,'big')+cert_entry)
        transcript+=ee+cert
        signature=key.sign(bytes([32])*64+b'TLS 1.3, server CertificateVerify\0'+hashlib.sha256(transcript).digest())
        if corrupt_verify:signature=bytes([signature[0]^1])+signature[1:]
        cv=message(15,b'\x08\x07'+struct.pack('!H',len(signature))+signature);transcript+=cv
        finished=extract(expand(server_hs,b'finished',b'',32),hashlib.sha256(transcript).digest())
        if corrupt_finished:finished=bytes([finished[0]^1])+finished[1:]
        sf=message(20,finished);transcript+=sf
        sock.sendall(server_records.encrypt(22,ee+cert+cv+sf))
        master=extract(derive(secret,b'derived',b''),bytes(32))
        self.receive_keys=RecordKeys(derive(master,b'c ap traffic',transcript))
        self.send_keys=RecordKeys(derive(master,b's ap traffic',transcript))
        kind,data=self.read_record(client_records)
        if kind!=22 or data[:4]!=b'\x14\0\0\x20':raise ValueError('TLS client Finished framing')
        expected=extract(expand(client_hs,b'finished',b'',32),hashlib.sha256(transcript).digest())
        if not hmac.compare_digest(data[4:],expected):raise ValueError('TLS client Finished verification')

    def read_record(self,keys):
        while True:
            head=exact(self.socket,5);n=int.from_bytes(head[3:5],'big')
            if n>16640:raise ValueError('TLS record length')
            data=exact(self.socket,n)
            if head[0]==20 and data==b'\1':continue
            if head[:3]!=b'\x17\3\3':raise EOFError('TLS peer terminated handshake')
            kind,plain=keys.decrypt(head,data)
            if kind==21:raise EOFError('TLS alert')
            return kind,plain

    def recv(self,n):
        while not self.buffer and not self.ended:
            try:kind,data=self.read_record(self.receive_keys)
            except EOFError:self.ended=True;break
            if kind!=23:raise ValueError('unexpected TLS application content')
            self.buffer+=data
        out=bytes(self.buffer[:n]);del self.buffer[:n];return out
    def sendall(self,data):
        for p in range(0,len(data),16384):self.socket.sendall(self.send_keys.encrypt(23,data[p:p+16384]))
    def close(self):
        try:self.socket.sendall(self.send_keys.encrypt(21,b'\1\0'))
        except OSError:pass
        self.socket.close()
