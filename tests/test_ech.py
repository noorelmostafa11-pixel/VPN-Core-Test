"""Actual ECH acceptance, rejection and configured DNS resolver transports."""
import base64
import concurrent.futures
import contextlib
import hashlib
import http.server
import json
import random
import socket
import ssl
import struct
import subprocess
import threading
import unittest
from urllib.parse import quote
import test_expanded as old
from test_core import exact,ROOT


def answer(query,config):
    if len(query)<12 or query[4:6]!=b'\0\1':raise ValueError('DNS fixture question')
    record=b'\0\1\0'+struct.pack('!HH',5,len(config))+config
    return query[:2]+b'\x81\x80\0\1\0\1\0\0\0\0'+query[12:]+b'\xc0\x0c\0A\0\1\0\0\0\x3c'+struct.pack('!H',len(record))+record


class Resolver:
    def __init__(self,scheme,config,context=None):
        self.scheme=scheme;self.config=config;self.context=context;self.queries=0
        self.stop=threading.Event();self.socket=socket.socket(type=socket.SOCK_DGRAM if scheme=='udp' else socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1',0));self.port=self.socket.getsockname()[1];self.socket.settimeout(.2)
        if scheme!='udp':self.socket.listen(8)
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while not self.stop.is_set():
            try:
                if self.scheme=='udp':
                    query,address=self.socket.recvfrom(65536);self.queries+=1;self.socket.sendto(answer(query,self.config),address)
                else:
                    raw,_=self.socket.accept();raw.settimeout(5)
                    with self.context.wrap_socket(raw,server_side=True) if self.scheme=='tls' else raw as conn:
                        n=int.from_bytes(exact(conn,2),'big');query=exact(conn,n);self.queries+=1;response=answer(query,self.config);conn.sendall(struct.pack('!H',len(response))+response)
            except socket.timeout:continue
            except (EOFError,OSError):continue
    def close(self):self.stop.set();self.socket.close();self.thread.join(1)


class ECHTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    socks=old.ExpandedTests.socks
    @contextlib.contextmanager
    def peer(self,reject=False,target=None,retry=False):
        args=[str(ROOT/'bin/ech-peer'),'--cert',str(old.original.CoreTests.cert),'--key',str(old.original.CoreTests.key)]
        if reject:args.append('--reject')
        if retry:args.append('--retry')
        if target:args+=['--target',target]
        process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            info=json.loads(process.stdout.readline());yield info
        finally:process.terminate();process.wait(3);process.stdout.close();process.stderr.close()
    def uri(self,p,ech,fp='chrome'):
        return f'vless://{old.ID}@127.0.0.1:{p["port"]}?security=tls&sni=localhost&fp={fp}&ech='+quote(ech,safe='')
    def exchange(self,p,ech,fp='chrome'):
        with self.core(self.uri(p,ech,fp)) as (port,log):
            try:s=self.socks(port)
            except Exception:raise AssertionError(log.read_text())
            with s:
                self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                payload=random.Random(649).randbytes(160007)
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    writer=pool.submit(s.sendall,payload);self.assertEqual(hashlib.sha256(exact(s,len(payload))).digest(),hashlib.sha256(payload).digest());writer.result(5)
    def test_01_direct_config_and_profiles(self):
        with self.peer() as p:
            for fp in ['chrome','firefox','native']:
                with self.subTest(fp=fp):self.exchange(p,p['ech'],fp)
    def test_02_configured_udp_tcp_dot(self):
        with self.peer() as p:
            for scheme in ['udp','tcp','tls']:
                for separator in ['+',' ']:
                    with self.subTest(scheme=scheme,separator=separator):
                        resolver=Resolver(scheme,base64.b64decode(p['ech']),self.context)
                        try:self.exchange(p,'localhost'+separator+f'{scheme}://127.0.0.1:{resolver.port}');self.assertEqual(resolver.queries,1)
                        finally:resolver.close()
    def test_03_configured_doh(self):
        with self.peer() as p:
            config=base64.b64decode(p['ech']);queries=[]
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_POST(self):
                    query=self.rfile.read(int(self.headers['content-length']));queries.append(query)
                    response=answer(query,config);self.send_response(200);self.send_header('Content-Type','application/dns-message');self.send_header('Content-Length',str(len(response)));self.end_headers();self.wfile.write(response)
                def log_message(self,*args):pass
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key)
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(['http/1.1'])
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:self.exchange(p,f'localhost+https://127.0.0.1:{server.server_port}/dns-query');self.assertEqual(len(queries),1)
            finally:server.shutdown();server.server_close();thread.join(2)
    def test_04_rejection_does_not_fallback(self):
        with self.peer(reject=True) as p:
            with self.core(self.uri(p,p['ech'])+'&allowInsecure=1') as (port,log):
                s=socket.create_connection(('127.0.0.1',port),5);s.settimeout(8);s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0')
                s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(s,10)[1],0);s.close()

    def test_05_ech_with_websocket_and_upgrade(self):
        import test_ws_plugins
        for transport in ('websocket','httpupgrade'):
            p=test_ws_plugins.Peer('vless') if transport=='websocket' else old.Peer('vless',transport='httpupgrade')
            try:
                with self.peer(target=f'127.0.0.1:{p.port}') as info:
                    for fp in ('chrome','firefox','native'):
                        uri=self.uri(info,info['ech'],fp)+'&type='+('ws' if transport=='websocket' else transport)+'&path=%2Ftest'
                        with self.core(uri) as (port,log):
                            try:s=self.socks(port)
                            except Exception as e:
                                raise AssertionError(fp+' '+transport+' '+log.read_text()+repr(p.errors)) from e
                            with s:
                                self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                                payload=random.Random(331).randbytes(160007);s.sendall(payload)
                                self.assertEqual(hashlib.sha256(exact(s,len(payload))).digest(),hashlib.sha256(payload).digest())
                self.assertEqual(p.errors,[])
            finally:p.close()

    def test_06_ech_hello_retry_request(self):
        with self.peer(retry=True) as p:
            for fp in ('chrome','firefox','native'):
                with self.subTest(fp=fp):self.exchange(p,p['ech'],fp)

if __name__=='__main__':unittest.main(verbosity=2)
