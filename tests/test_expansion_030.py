"""Independent wire peers for the 0.3 expansion; no public network dependency."""
import concurrent.futures
import hashlib
import json
import pathlib
import os
import random
import socket
import ssl
import struct
import subprocess
import time
import threading
import unittest
from unittest.mock import patch
from urllib.parse import quote, urlsplit, parse_qs
import test_expanded as old
from test_core import exact, ROOT, BIN
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded
from h2.settings import SettingCodes

class XWire:
    def __init__(self,sock,transport,bad=False,path=''):
        self.sock=sock; self.buffer=bytearray(); self.ended=False
        self.http2=isinstance(sock,ssl.SSLSocket) and sock.selected_alpn_protocol()=='h2'
        if self.http2:
            self.h2=H2Connection(config=H2Configuration(client_side=False,header_encoding='utf-8'))
            self.h2.initiate_connection()
            self.h2.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 1031})
            sock.sendall(self.h2.data_to_send())
            while not hasattr(self,'stream'): self.pump()
        else:
            header=b''
            while not header.endswith(b'\r\n\r\n'): header+=exact(sock,1)
            lines=header.decode().split('\r\n')
            self.validate({x.split(': ',1)[0].lower():x.split(': ',1)[1] for x in lines[1:] if ': ' in x},lines[0].split()[1])
            if lines[0]!='POST /test/ HTTP/1.1': raise ValueError('XHTTP request')
            if b'Transfer-Encoding: chunked' not in header: raise ValueError('XHTTP upload framing')
            # Fragment both headers and chunk delimiters to exercise streaming.
            for b in b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n': sock.sendall(bytes([b]))
    def validate(self,headers,path):
        if path!='/test/': raise ValueError('XHTTP path')
        padding=parse_qs(urlsplit(headers['referer']).query)['x_padding'][0]
        if not 100<=len(padding)<=1000 or set(padding)!={'X'}: raise ValueError('XHTTP padding')
        if headers.get('accept-encoding')!='identity': raise ValueError('XHTTP accept encoding')
        if headers.get('content-type','application/grpc')!='application/grpc': raise ValueError('XHTTP content type')
    def pump(self):
        data=self.sock.recv(16384)
        if not data: self.ended=True; return
        for event in self.h2.receive_data(data):
            if isinstance(event,RequestReceived):
                headers=dict(event.headers);self.validate(headers,headers[':path'])
                if headers[':method']!='POST': raise ValueError('XHTTP method')
                self.stream=event.stream_id
                self.h2.send_headers(self.stream,[(':status','200'),('content-type','text/event-stream')])
            elif isinstance(event,DataReceived):
                self.buffer+=event.data
                self.h2.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
            elif isinstance(event,StreamEnded):
                self.ended=True;self.h2.end_stream(self.stream)
        self.sock.sendall(self.h2.data_to_send())
    def recv(self,n):
        while not self.buffer and not self.ended:
            if self.http2: self.pump()
            else:
                line=b''
                while not line.endswith(b'\r\n'): line+=exact(self.sock,1)
                length=int(line[:-2],16)
                if length==0:
                    if exact(self.sock,2)!=b'\r\n': raise ValueError('end chunk')
                    self.ended=True;self.sock.sendall(b'0\r\n\r\n');break
                self.buffer+=exact(self.sock,length)
                if exact(self.sock,2)!=b'\r\n': raise ValueError('chunk delimiter')
        out=bytes(self.buffer[:n]);del self.buffer[:n];return out
    def sendall(self,data):
        if self.http2:
            pos=0
            while pos<len(data):
                window=self.h2.local_flow_control_window(self.stream)
                if window<=0: self.pump();continue
                n=min(window,self.h2.max_outbound_frame_size,len(data)-pos)
                self.h2.send_data(self.stream,data[pos:pos+n]);pos+=n;self.sock.sendall(self.h2.data_to_send())
        else:
            wire=f'{len(data):x};oracle=yes\r\n'.encode()+data+b'\r\n'
            for p in range(0,len(wire),1031): self.sock.sendall(wire[p:p+1031])

class HeaderWire:
    def __init__(self,sock,*args):
        self.sock=sock;header=b''
        while not header.endswith(b'\r\n\r\n'): header+=exact(sock,1)
        if not header.startswith(b'GET /test HTTP/1.1\r\n'): raise ValueError('raw HTTP request')
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n')
    def recv(self,n): return self.sock.recv(n)
    def sendall(self,data): self.sock.sendall(data)

OriginalWire=old.Wrapped
def factory(sock,transport,*args):
    if transport=='xhttp': return XWire(sock,transport,*args)
    if transport=='header': return HeaderWire(sock,*args)
    return OriginalWire(sock,transport,*args)

class ExpansionTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    uri=old.ExpandedTests.uri
    socks=old.ExpandedTests.socks
    def probe(self,value):
        r=subprocess.run([os.environ.get('VPN_CORE_EXPANSION_PROBE',str(ROOT/'bin/expansion-probe'))],input=json.dumps(value)+'\n',text=True,capture_output=True,check=True)
        return json.loads(r.stdout)
    def exchange(self,protocol='vless',cipher='',transport='raw',tls=False,options='',length=65536):
        with patch.object(old,'Wrapped',factory):
            peer=old.Peer(protocol,cipher,transport,self.context if tls else None)
            try:
                uri=self.uri(peer)
                if transport=='xhttp': uri+='&mode=stream-one'
                if transport=='header': uri=uri.replace('type=header','type=raw')+'&headerType=http'
                with self.core(uri+options) as (port,log):
                    with self.socks(port) as s:
                        self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                        body=random.Random(803).randbytes(length)
                        with concurrent.futures.ThreadPoolExecutor() as pool:
                            writer=pool.submit(s.sendall,body)
                            self.assertEqual(hashlib.sha256(exact(s,len(body))).digest(),hashlib.sha256(body).digest())
                            writer.result(10)
                    self.assertIn('diagnostic=',log.read_text())
                self.assertEqual(peer.errors,[])
            finally: peer.close()
    def test_01_fragment_tls_records(self):
        payload=bytes(range(32));record=b'\x16\x03\x01'+struct.pack('!H',len(payload))+payload;tail=b'next-record'
        fm={'tcp':[{'type':'fragment','settings':{'packets':'tlshello','lengths':['0','4','1'],'delays':['0'],'maxSplit':'5'}}]}
        rows=self.probe({'fm':fm,'parts':[(record+tail).hex(),record.hex()]})
        self.assertEqual(len(rows[0]),2) # zero-delay TLS records merge into one write
        wire=bytes.fromhex(rows[0][0]['data']);parts=[]
        while wire:
            self.assertEqual(wire[:3],record[:3]);n=int.from_bytes(wire[3:5],'big');parts.append(wire[5:5+n]);wire=wire[5+n:]
        self.assertEqual([len(x) for x in parts],[0,4,1,1,26]);self.assertEqual(b''.join(parts),payload)
        self.assertEqual(bytes.fromhex(rows[0][1]['data']),tail)
        self.assertEqual(rows[1],[{'data':record.hex(),'delay_ms':0}])
    def test_02_fragment_chaining_and_delays(self):
        fm={'tcp':[{'type':'fragment','settings':{'packets':'1-1','length':'5','delay':'1','maxSplit':'3'}},{'type':'fragment','settings':{'packets':'1-1','lengths':['0','2'],'delays':['0','2'],'maxSplit':'3'}}]}
        body=b'0123456789abcdef'
        rows=self.probe({'fm':fm,'parts':[body.hex(),body.hex()]})
        self.assertEqual(b''.join(bytes.fromhex(x['data']) for x in rows[0]),body)
        self.assertEqual([len(bytes.fromhex(x['data'])) for x in rows[0]],[0,2,3,5,6])
        self.assertEqual([x['delay_ms'] for x in rows[0]],[0,2,3,1,1])
        self.assertEqual(rows[1],[{'data':body.hex(),'delay_ms':0}])
    def test_03_fragment_tls_interop(self):
        fm={'tcp':[{'type':'fragment','settings':{'packets':'tlshello','lengths':['0','104','1'],'delays':['0'],'maxSplit':'11'}},{'type':'fragment','settings':{'packets':'1-1','lengths':['114','1'],'delays':['1'],'maxSplit':'11'}}]}
        self.exchange('trojan',tls=True,options='&fm='+quote(json.dumps(fm),safe=''))
    def test_04_fragment_plain_interop(self):
        fm={'tcp':[{'type':'fragment','settings':{'packets':'1-2','length':'1-3','delay':'0','maxSplit':'0'}}]}
        self.exchange('vmess','chacha20-poly1305',options='&fm='+quote(json.dumps(fm),safe=''))
    def test_05_raw_http_header(self): self.exchange(transport='header')
    def test_06_raw_http_header_tls(self): self.exchange('trojan',transport='header',tls=True)
    def test_07_xhttp_http1(self): self.exchange(transport='xhttp')
    def test_08_xhttp_http2_flow_control(self): self.exchange(transport='xhttp',tls=True,length=3*1024*1024)
    def test_09_xhttp_vmess(self): self.exchange('vmess','aes-128-gcm','xhttp',True)
    def test_10_xhttp_trojan_options(self): self.exchange('trojan',transport='xhttp',tls=True,options='&extra='+quote(json.dumps({'noGRPCHeader':True,'headers':{'X-Test':'test'},'xmux':{'maxConnections':1}}),safe=''))
    def test_11_unsafe_keeps_certificate_verification(self): self.exchange('trojan',tls=True,options='&fp=unsafe')
    def test_12_inactive_fingerprint(self): self.exchange(options='&fp=chrome')
    def test_13_chunk_decoder_and_rejection(self):
        wire=b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=yes\r\nabc\r\n2\r\nde\r\n0\r\nX-Test: valid\r\n\r\n'
        row=self.probe({'op':'http','parts':[bytes([b]).hex() for b in wire]})
        self.assertEqual(row,{'data':b'abcde'.hex(),'closed':True})
        for wire in [b'HTTP/1.1 403 Forbidden\r\n\r\n',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n']:
            self.assertIn('error',self.probe({'op':'http','parts':[wire.hex()]}))
    def test_14_unknown_options_rejected(self):
        cases=[('&mode=future-invalid-mode','PARSE_INVALID'),('&mode=stream-one&extra='+quote('{"futureUnknownKey":true}',safe=''),'FEATURE_UNIMPLEMENTED'),('&mode=stream-one&extra='+quote('{"headers":{"Content-Length":"0"}}',safe=''),'PARSE_INVALID')]
        for option,reason in cases:
            with self.subTest(option=option):
                import tempfile
                with tempfile.TemporaryDirectory(dir=self.directory) as d:
                    f=pathlib.Path(d)/'node.ini';f.write_text(f'node_uri=vless://{old.ID}@127.0.0.1:443?type=xhttp&security=tls{option}\n')
                    r=subprocess.run([str(BIN),'--config',str(f),'--check-config'],capture_output=True,text=True)
                    self.assertNotEqual(r.returncode,0);self.assertIn(reason,r.stderr)
    def test_15_reversed_ranges_and_empty_split(self):
        body=b'abcdef'
        fm={'tcp':[{'type':'fragment','settings':{'packets':'1-1','length':'3-1','delay':'0','maxSplit':''}}]}
        rows=self.probe({'fm':fm,'parts':[body.hex()]})
        self.assertEqual(b''.join(bytes.fromhex(x['data']) for x in rows[0]),body)
        self.assertTrue(all(1<=len(bytes.fromhex(x['data']))<=3 for x in rows[0]))
    def test_19_legacy_finalmask_interval(self):
        fm={'outbounds':[{'protocol':'freedom','settings':{'fragment':{'packets':'tlshello','length':'100-200','interval':'0'}}}]}
        self.exchange('trojan',tls=True,options='&fm='+quote(json.dumps(fm),safe=''))
    def test_16_unsafe_rejects_wrong_certificate_name(self):
        peer=old.Peer('trojan',tls_context=self.context)
        try:
            with self.core(self.uri(peer).replace('sni=localhost','sni=wrong-name.invalid')+'&fp=unsafe') as (port,log):
                with socket.create_connection(('127.0.0.1',port),5) as sock:
                    sock.settimeout(5);sock.sendall(b'\5\1\0');self.assertEqual(exact(sock,2),b'\5\0')
                    sock.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(sock,10)[1],0)
                deadline=time.monotonic()+1
                while 'TLS_HANDSHAKE_VERIFY' not in log.read_text() and time.monotonic()<deadline:time.sleep(.01)
                self.assertIn('TLS_HANDSHAKE_VERIFY',log.read_text())
            self.assertEqual(peer.accepted,0)
        finally:peer.close()
    def test_17_fragment_socket_backpressure(self):
        body=random.Random(190).randbytes(262144);received=[];errors=[]
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(10)
        def slow_reader():
            try:
                with listener.accept()[0] as sock:
                    sock.settimeout(10);time.sleep(.1);chunks=[]
                    while sum(map(len,chunks))<len(body):
                        data=sock.recv(4096)
                        if not data:raise EOFError('fragmented stream truncated')
                        chunks.append(data);time.sleep(.001)
                    received.append(b''.join(chunks))
            except Exception as e:errors.append(repr(e))
        reader=threading.Thread(target=slow_reader);reader.start()
        try:
            fm={'tcp':[{'type':'fragment','settings':{'packets':'1-1','lengths':['0','4096'],'delays':['0'],'maxSplit':'355'}}]}
            result=self.probe({'op':'socket','port':listener.getsockname()[1],'fm':fm,'data':body.hex()})
            reader.join(12);self.assertFalse(reader.is_alive());self.assertEqual(errors,[]);self.assertEqual(received,[body]);self.assertEqual(result['bytes'],len(body));self.assertGreater(result['partial_retries'],0)
        finally:listener.close()
if __name__=='__main__':unittest.main(verbosity=2)
