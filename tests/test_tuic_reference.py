"""Independent TUIC v5 reference: pinned official sing-box binary, test-only."""
import contextlib,hashlib,json,os,pathlib,shutil,socket,ssl,subprocess,tempfile,threading,time,unittest
from test_core import BIN,exact,free_port
import test_hysteria_reference as hyref

UUID='12345678-1234-4567-9234-567812345678'
class TUICReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference=pathlib.Path(os.environ.get('VPN_CORE_REFERENCE_SINGBOX',''))
        if not cls.reference.is_file():raise unittest.SkipTest('set VPN_CORE_REFERENCE_SINGBOX to sing-box 1.14.3 executable')
    def socks(self,*args):return hyref.HysteriaReferenceTests.socks(self,*args)
    @contextlib.contextmanager
    def pair(self,project_server,mode,bad_auth=False):
        with tempfile.TemporaryDirectory(prefix='vpn-tuic-reference-') as temp:
            root=pathlib.Path(temp);cert,key=root/'cert.pem',root/'key.pem';server,socks=free_port(),free_port()
            openssl=shutil.which('openssl')
            if not openssl and os.name=='nt':openssl=str(pathlib.Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Git/usr/bin/openssl.exe')
            if not openssl:raise unittest.SkipTest('OpenSSL needed for synthetic TLS certificate')
            subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            password='wrong' if bad_auth else 'synthetic-auth'
            if project_server:
                project={'outbounds':[{'tag':'direct','uri':'direct://'}],'final':'direct','inbounds':[{'protocol':'tuic','listen':f'127.0.0.1:{server}','uuids':[UUID],'password':'synthetic-auth','cert_file':str(cert),'key_file':str(key)}]}
                reference={'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks}],'outbounds':[{'type':'tuic','server':'127.0.0.1','server_port':server,'uuid':UUID,'password':password,'udp_relay_mode':mode,'tls':{'enabled':True,'alpn':['h3'],'server_name':'localhost','certificate_path':str(cert)}}]}
            else:
                reference={'inbounds':[{'type':'tuic','listen':'127.0.0.1','listen_port':server,'users':[{'uuid':UUID,'password':'synthetic-auth'}],'tls':{'enabled':True,'alpn':['h3'],'certificate_path':str(cert),'key_path':str(key)}}],'outbounds':[{'type':'direct'}]}
                # CA is top-level because the node URI intentionally carries no local file paths.
                uri=f'tuic://{UUID}:{password}@127.0.0.1:{server}?sni=localhost&pinsha256={pin}&udp-relay-mode={mode}'
                project={'listen_port':socks,'outbounds':[{'tag':'tuic','uri':uri}],'final':'tuic'}
            pp,rp=root/'project.json',root/'reference.json';pp.write_text(json.dumps(project),encoding='utf-8');rp.write_text(json.dumps(reference),encoding='utf-8')
            processes=[]
            with (root/'project.log').open('w') as plog,(root/'reference.log').open('w') as rlog:
                try:
                    project_cmd=[str(BIN),'--config',str(pp)]+(['--no-socks'] if project_server else [])
                    ref_cmd=[str(self.reference),'run','-c',str(rp)]
                    commands=[(project_cmd,plog),(ref_cmd,rlog)] if project_server else [(ref_cmd,rlog),(project_cmd,plog)]
                    for args,log in commands:processes.append(subprocess.Popen(args,stdout=log,stderr=log))
                    deadline=time.monotonic()+6
                    while True:
                        if any(p.poll() is not None for p in processes):self.fail('TUIC process stopped before readiness')
                        try:
                            with socket.create_connection(('127.0.0.1',socks),.2):break
                        except OSError:
                            if time.monotonic()>deadline:self.fail('TUIC readiness timeout')
                            time.sleep(.03)
                    yield socks
                except BaseException as error:
                    plog.flush();rlog.flush();error.add_note((root/'project.log').read_text(errors='replace')[-3000:]);error.add_note((root/'reference.log').read_text(errors='replace')[-3000:]);raise
                finally:
                    for p in reversed(processes):
                        if p.poll() is None:p.terminate()
                        try:p.wait(timeout=5)
                        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
    def test_reference_tcp_udp_both_modes_and_directions(self):
        for project_server in [False,True]:
            for mode in ['native','quic']:
                with self.subTest(project_server=project_server,mode=mode),socket.socket() as tcp,socket.socket(type=socket.SOCK_DGRAM) as udp:
                    tcp.bind(('127.0.0.1',0));tcp.listen();tcp.settimeout(.2);udp.bind(('127.0.0.1',0));udp.settimeout(.2);stop=threading.Event();workers=[]
                    def handle(c):
                        try:
                            with c:
                                c.settimeout(4)
                                while data:=c.recv(65535):c.sendall(data)
                        except OSError:pass
                    def accept():
                        while not stop.is_set():
                            try:c,_=tcp.accept()
                            except OSError:continue
                            w=threading.Thread(target=handle,args=(c,));workers.append(w);w.start()
                    def echo_udp():
                        while not stop.is_set():
                            try:data,a=udp.recvfrom(65535);udp.sendto(data,a)
                            except OSError:continue
                    listeners=[threading.Thread(target=accept),threading.Thread(target=echo_udp)]
                    for w in listeners:w.start()
                    try:
                        with self.pair(project_server,mode) as socks:
                            for cycle in range(16):
                                c,_=self.socks(socks,1,tcp.getsockname())
                                with c:
                                    body=b'TUIC independent TCP payload\x00\xff'*256;c.sendall(body);self.assertEqual(exact(c,len(body)),body)
                            control,relay=self.socks(socks,3,('0.0.0.0',0))
                            with control,socket.socket(type=socket.SOCK_DGRAM) as client:
                                client.bind(('127.0.0.1',0));client.settimeout(5)
                                header=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+udp.getsockname()[1].to_bytes(2,'big')
                                # Reference Windows direct/SOCKS UDP buffers are
                                # 4 KiB by default; large fragmentation is covered
                                # by the Go 60 KiB tests, not inferred here.
                                for size in [32,1400,3800]:
                                    body=b't'*size;client.sendto(header+body,relay);r,_=client.recvfrom(65535);self.assertEqual(r[10:],body)
                    finally:
                        stop.set()
                        for w in listeners:w.join(timeout=2);self.assertFalse(w.is_alive())
                        for w in workers:w.join(timeout=5);self.assertFalse(w.is_alive())
