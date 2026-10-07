"""Real PowerShell scheduler: eight concurrent expanded tunnels to local HTTPS."""
import hashlib
import json
import os
import pathlib
import select
import socket
import ssl
import subprocess
import struct
import tempfile
import threading
import unittest
from urllib.parse import quote
import test_core as original
from test_core import exact, ROOT, BIN
from test_batch import Service, PW, BODY, ID
from test_expansion_030 import XWire, HeaderWire, OriginalWire

@unittest.skipUnless(PW,'Set VPN_CORE_POWERSHELL')
class ExpandedBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): original.CoreTests.setUpClass()
    @classmethod
    def tearDownClass(cls): original.CoreTests.tearDownClass()
    def test_eight_expanded_tunnels_and_safe_failure_details(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(original.CoreTests.cert,original.CoreTests.key)
        context.set_alpn_protocols(['h2','http/1.1'])
        origin_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        origin_context.load_cert_chain(original.CoreTests.cert,original.CoreTests.key)
        origin_context.set_alpn_protocols(['http/1.1'])
        def origin(raw):
            with origin_context.wrap_socket(raw,server_side=True) as sock:
                data=b''
                while b'\r\n\r\n' not in data: data+=sock.recv(8192)
                sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(BODY)).encode()+b'\r\nConnection: close\r\n\r\n'+BODY)
                try:sock.unwrap().close()
                except (OSError,ssl.SSLError):pass
        target=Service(origin);peers=[];barrier=threading.Barrier(8);lock=threading.Lock();active=0;maximum=0
        def handler(transport,tls,protocol):
            def serve(raw):
                nonlocal active,maximum
                sock=context.wrap_socket(raw,server_side=True) if tls else raw
                try:
                    if transport=='xhttp': wire=XWire(sock,transport)
                    elif transport=='header':wire=HeaderWire(sock)
                    else:wire=OriginalWire(sock,transport)
                    if transport=='websocket':
                        # This duplex proxy must not block waiting for an
                        # application payload after a pong-only control frame.
                        def send_frame(data):
                            head=b'\x82'+bytes([len(data)]) if len(data)<126 else b'\x82\x7e'+struct.pack('!H',len(data))
                            sock.sendall(head+data)
                        wire.sendall=send_frame
                    if protocol=='trojan':
                        if exact(wire,56)!=hashlib.sha224(b'synthetic-batch-secret').hexdigest().encode() or exact(wire,3)!=b'\r\n\1':raise ValueError('Trojan auth')
                        if exact(wire,1)!=b'\1' or exact(wire,4)!=b'\x7f\0\0\1':raise ValueError('Trojan address')
                        port=int.from_bytes(exact(wire,2),'big')
                        if exact(wire,2)!=b'\r\n':raise ValueError('Trojan delimiter')
                    else:
                        if exact(wire,18)!=b'\0'+bytes.fromhex(ID.replace('-',''))+b'\0' or exact(wire,1)!=b'\1':raise ValueError('VLESS auth')
                        port=int.from_bytes(exact(wire,2),'big')
                        if exact(wire,1)!=b'\1' or exact(wire,4)!=b'\x7f\0\0\1':raise ValueError('VLESS destination')
                        wire.sendall(b'\0\0')
                    if port!=target.port:raise ValueError('origin port')
                    with lock:active+=1;maximum=max(maximum,active)
                    try:
                        barrier.wait(10)
                        with socket.create_connection(('127.0.0.1',port),5) as remote:
                            while True:
                                buffered=getattr(wire,'buffer',b'') or (isinstance(sock,ssl.SSLSocket) and sock.pending())
                                reads=[sock] if buffered else select.select([sock,remote],[],[],10)[0]
                                if not reads:return
                                for source in reads:
                                    if source is sock and transport=='xhttp' and wire.http2:
                                        if not wire.buffer:wire.pump()
                                        data=bytes(wire.buffer);wire.buffer.clear()
                                        if not data and not wire.ended:continue
                                    else:data=wire.recv(16384) if source is sock else remote.recv(16384)
                                    if not data:return
                                    if source is sock:remote.sendall(data)
                                    else:wire.sendall(data)
                    finally:
                        with lock:active-=1
                finally:sock.close()
            return serve
        fm={'tcp':[{'type':'fragment','settings':{'packets':'tlshello','lengths':['0','104','1'],'delays':['0'],'maxSplit':'11'}},{'type':'fragment','settings':{'packets':'1-1','lengths':['114','1'],'delays':['1'],'maxSplit':'11'}}]}
        variants=[('vless','xhttp',False,''),('vless','xhttp',True,''),('trojan','xhttp',True,'&fp=unsafe'),('vless','header',False,''),('trojan','header',True,'&fm='+quote(json.dumps(fm),safe='')),('vless','websocket',True,'&fp=unsafe'),('trojan','raw',True,'&fm='+quote(json.dumps(fm),safe='')),('vless','raw',False,'&fp=chrome')]
        try:
            lines=[]
            for protocol,transport,tls,options in variants:
                peer=Service(handler(transport,tls,protocol));peers.append(peer)
                query=f'?security={"tls" if tls else "none"}&type={"raw" if transport=="header" else transport}&path=%2Ftest&sni=localhost'
                if transport=='header':query+='&headerType=http'
                if transport=='xhttp':query+='&mode=stream-one'
                credential='synthetic-batch-secret' if protocol=='trojan' else ID
                lines.append(f'{protocol}://{credential}@127.0.0.1:{peer.port}'+query+options)
            def denied(sock):
                data=b''
                while b'\r\n\r\n' not in data:data+=sock.recv(8192)
                sock.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Secret: do-not-export\r\n\r\n')
            deny=Service(denied);peers.append(deny)
            lines.append(f'vless://{ID}@127.0.0.1:{deny.port}?security=none&type=ws&path=/test')
            badcert=Service(handler('raw',True,'trojan'));peers.append(badcert)
            lines.append(f'trojan://synthetic-batch-secret@127.0.0.1:{badcert.port}?security=tls&fp=unsafe&sni=wrong-name.invalid')
            with tempfile.TemporaryDirectory(dir=original.CoreTests.directory) as temp:
                temp=pathlib.Path(temp);nodes=temp/'nodes.txt';nodes.write_text('\n'.join(lines)+'\n');output=temp/'reports'
                r=subprocess.run([PW,'-NoProfile','-File',str(ROOT/'scripts/Test-Batch.ps1'),'-Core',str(BIN),'-Curl','curl','-Nodes',str(nodes),'-Concurrency','8','-TimeoutSeconds','20','-TestCaFile',str(original.CoreTests.ca),'-Url',f'https://127.0.0.1:{target.port}/','-ExpectedBodySha256',hashlib.sha256(BODY).hexdigest(),'-OutputDirectory',str(output)],capture_output=True,text=True,timeout=90)
                self.assertEqual(r.returncode,0,r.stdout+r.stderr)
                self.assertEqual(target.errors+sum((x.errors for x in peers),[]),[])
                rows=[json.loads(l) for l in (output/'results.ndjson').read_text().splitlines()]
                passed=[x for x in rows if x['status']=='PASS'];failed=[x for x in rows if x['status']=='FAIL']
                self.assertEqual(len(passed),8,rows);self.assertEqual(len(failed),2,rows);self.assertEqual(maximum,8)
                self.assertTrue(all(x['body_sha256']==hashlib.sha256(BODY).hexdigest() for x in passed))
                self.assertEqual({x['reason_code'] for x in failed},{'HTTP_UPGRADE_STATUS','TLS_HANDSHAKE_VERIFY'})
                self.assertEqual(next(x for x in failed if x['reason_code']=='HTTP_UPGRADE_STATUS')['transport_http_status'],403)
                self.assertNotEqual(next(x for x in failed if x['reason_code']=='TLS_HANDSHAKE_VERIFY')['native_status'],0)
                for file in output.iterdir():
                    text=file.read_text(encoding='utf-8-sig')
                    for secret in (ID,'synthetic-batch-secret','do-not-export','vless://','trojan://'):self.assertNotIn(secret,text)
                summary=json.loads((output/'summary.json').read_text());summary['observed_max_concurrent_tunnels']=maximum
                (ROOT/'docs/expansion-030-batch-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
                (ROOT/'docs/expansion-030-batch-results.ndjson').write_text((output/'results.ndjson').read_text())
                (ROOT/'docs/expansion-030-batch-output.txt').write_text(r.stdout+r.stderr)
            self.assertEqual(target.errors+sum((x.errors for x in peers),[]),[])
        finally:
            for peer in peers:peer.close()
            target.close()
if __name__=='__main__':unittest.main(verbosity=2)
