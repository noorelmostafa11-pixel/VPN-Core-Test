"""Vision framing and direct receive verified through an inner TLS session."""
import concurrent.futures
import hashlib
import os
import random
import socket
import ssl
import struct
import threading
import time
import unittest
import test_expanded as old
from test_core import exact


class MemoryTLS:
    def __init__(self,sock,context):
        self.socket=sock;self.input=ssl.MemoryBIO();self.output=ssl.MemoryBIO()
        self.tls=context.wrap_bio(self.input,self.output,server_side=True)
        while True:
            try:self.tls.do_handshake();self.flush();break
            except ssl.SSLWantReadError:self.flush();self.receive()
    def flush(self):
        data=self.output.read()
        if data:self.socket.sendall(data)
    def receive(self):
        data=self.socket.recv(65536)
        if not data:raise EOFError('TLS socket EOF')
        self.input.write(data)
    def recv(self,n):
        while True:
            try:return self.tls.read(n)
            except ssl.SSLWantReadError:self.flush();self.receive()
    def ciphertext(self,data):
        for offset in range(0,len(data),16384):self.tls.write(data[offset:offset+16384])
        return self.output.read()
    def sendall(self,data):self.socket.sendall(self.ciphertext(data))
    def close(self):self.socket.close()


class VisionReader:
    def __init__(self,wire):self.wire=wire;self.start=True;self.end=False;self.buffer=bytearray()
    def recv(self,n):
        if self.end and not self.buffer:return self.wire.recv(n)
        while not self.buffer:
            if self.start:
                if exact(self.wire,16)!=old.ID.bytes:raise ValueError('Vision UUID')
                self.start=False
            command,length,padding=struct.unpack('!BHH',exact(self.wire,5))
            if command not in [0,1]:raise ValueError('unexpected Vision writer command')
            self.buffer+=exact(self.wire,length);exact(self.wire,padding)
            self.end=command==1
            if self.end and not self.buffer:return self.wire.recv(n)
        out=bytes(self.buffer[:n]);del self.buffer[:n];return out


class VisionPeer(old.Peer):
    def __init__(self,context,inner=False,invalid=None,fragment_hello=False,plain=False):
        self.fragment_hello=fragment_hello;self.inner=inner;self.invalid=invalid;self.sent_prefix=False;self.direct=False
        self.inner_context=context
        self.local=threading.local()
        super().__init__('vless',tls_context=None if plain else context)
    def padding(self,command,data,padding=273):
        prefix=b'' if getattr(self.local,'sent_prefix',False) else old.ID.bytes;self.local.sent_prefix=True
        return prefix+struct.pack('!BHH',command,len(data),padding)+data+os.urandom(padding)
    def handle(self,raw):
        outer=None
        try:
            raw.settimeout(10);outer=MemoryTLS(raw,self.tls_context) if self.tls_context else raw
            if exact(outer,17)!=b'\0'+old.ID.bytes:raise ValueError('VLESS header')
            n=exact(outer,1)[0]
            if exact(outer,n)!=b'\x0a\x10xtls-rprx-vision':raise ValueError('Vision flow addon')
            if exact(outer,1)!=b'\1':raise ValueError('VLESS command')
            exact(outer,2);atyp=exact(outer,1)
            exact(outer,exact(outer,1)[0] if atyp==b'\2' else 4 if atyp==b'\1' else 16)
            reader=VisionReader(outer)
            if self.invalid is not None:
                outer.sendall(b'\0\0'+self.padding(self.invalid,old.HELLO))
                while outer.recv(16384):pass
                return
            if not self.inner:
                # A padding header and UUID can cross any TLS/socket boundary.
                wire=b'\0\0'+self.padding(0,old.HELLO[:5])+self.padding(1,old.HELLO[5:])+b'tail'
                for offset in range(0,len(wire),3):outer.sendall(wire[offset:offset+3])
                while True:
                    data=reader.recv(8192)
                    if not data:break
                    outer.sendall(data)
            else:
                incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
                inner=self.inner_context.wrap_bio(incoming,outgoing,server_side=True)
                outer.sendall(b'\0\0')
                while True:
                    try:inner.do_handshake();break
                    except ssl.SSLWantReadError:
                        response=outgoing.read()
                        if response:
                            if self.fragment_hello and response[0]==22:
                                n=int.from_bytes(response[3:5],'big');body=response[5:5+n]
                                response=b'\x16\x03\x03\x00\x03'+body[:3]+b'\x16\x03\x03'+(len(body)-3).to_bytes(2,'big')+body[3:]+response[5+n:]
                            outer.sendall(self.padding(0,response))
                        data=reader.recv(65536)
                        if not data:raise EOFError('inner TLS handshake EOF')
                        incoming.write(data)
                tickets=outgoing.read()
                if tickets:outer.sendall(self.padding(0,tickets))
                inner.write(old.HELLO)
                # The final padding spans two outer records. Direct bytes are
                # coalesced into the same TCP write as the transition record.
                transition=outer.ciphertext(self.padding(2,b'',21003))
                raw.sendall(transition+outgoing.read());self.direct=True
                while True:
                    try:
                        data=inner.read(16384)
                        if not data:break
                        inner.write(data);raw.sendall(outgoing.read())
                    except ssl.SSLWantReadError:
                        response=outgoing.read()
                        if response:raw.sendall(response)
                        data=reader.recv(65536)
                        if not data:break
                        incoming.write(data)
        except (EOFError,OSError,ssl.SSLError) as error:self.last_exception=repr(error)
        except Exception as e:self.errors.append(repr(e))
        finally:raw.close()


class VisionTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    uri=old.ExpandedTests.uri
    socks=old.ExpandedTests.socks
    def test_01_fragmented_padding_and_end(self):
        p=VisionPeer(self.context)
        try:
            with self.core(self.uri(p)+'&flow=xtls-rprx-vision&fp=chrome') as (port,log):
                with self.socks(port) as s:
                    self.assertEqual(exact(s,len(old.HELLO)+4),old.HELLO+b'tail')
                    s.sendall(b'after padding');self.assertEqual(exact(s,13),b'after padding')
            self.assertEqual(p.errors,[])
        finally:p.close()
    def test_02_direct_inner_tls_records(self):
        for fp,flow in [('chrome','xtls-rprx-vision'),('firefox','xtls-rprx-vision-udp443'),('native','xtls-rprx-vision'),('chrome','xtls-rprx-vision')]:
            with self.subTest(fp=fp,flow=flow):
                p=VisionPeer(self.context,inner=True,fragment_hello=True)
                try:
                    with self.core(self.uri(p)+f'&flow={flow}&fp={fp}') as (port,log):
                        context=ssl.create_default_context(cafile=self.ca)
                        context.minimum_version=ssl.TLSVersion.TLSv1_3
                        with context.wrap_socket(self.socks(port),server_hostname='localhost') as s:
                            self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                            payload=random.Random(756).randbytes(350007)
                            # An SSL object must have one owner. The payload fits
                            # the relay's bounded queues; TLS read/write calls are
                            # sequential while core and peer still run concurrently.
                            s.sendall(payload)
                            self.assertEqual(hashlib.sha256(exact(s,len(payload))).digest(),hashlib.sha256(payload).digest())
                    self.assertTrue(p.direct);self.assertEqual(p.errors,[])
                except BaseException as error:
                    time.sleep(.1)
                    error.add_note('Peer diagnostics: '+repr(p.errors)+'; last exception: '+str(getattr(p,'last_exception','none')))
                    raise
                finally:p.close()
    def test_03_unknown_command_and_unprotected_direct(self):
        for command,reason in [(4,'VISION_COMMAND'),(2,'VISION_DIRECT_SECURITY')]:
            p=VisionPeer(self.context,invalid=command)
            try:
                with self.core(self.uri(p)+'&flow=xtls-rprx-vision') as (port,log):
                    with self.socks(port) as s:
                        try:s.recv(100)
                        except ConnectionResetError:pass
                    deadline=time.monotonic()+2
                    while reason not in log.read_text() and time.monotonic()<deadline:time.sleep(.01)
                    self.assertIn(reason,log.read_text())
            finally:p.close()

if __name__=='__main__':unittest.main(verbosity=2)
