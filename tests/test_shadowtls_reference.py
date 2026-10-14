"""ShadowTLS v2/v3 + Shadowsocks/UOT, against pinned independent sing-box."""
import contextlib,hashlib,json,os,pathlib,shutil,socket,ssl,subprocess,tempfile,threading,time,unittest
from urllib.parse import quote
from test_core import BIN,exact,free_port
from test_ss_server_reference import secret
import test_hysteria_reference as hyref

class ShadowTLSReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference=pathlib.Path(os.environ.get('VPN_CORE_REFERENCE_SINGBOX',''))
        if not cls.reference.is_file():raise unittest.SkipTest('set VPN_CORE_REFERENCE_SINGBOX to sing-box 1.14.3 executable')
    def socks(self,*args):return hyref.HysteriaReferenceTests.socks(self,*args)
    @contextlib.contextmanager
    def pair(self,project_server,version,plugin=False,method='aes-256-gcm'):
        with tempfile.TemporaryDirectory(prefix='vpn-shadowtls-reference-') as temp:
            root=pathlib.Path(temp);cert,key=root/'cert.pem',root/'key.pem';server,socks,ss=free_port(),free_port(),free_port()
            openssl=shutil.which('openssl')
            if not openssl and os.name=='nt':openssl=str(pathlib.Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Git/usr/bin/openssl.exe')
            if not openssl:raise unittest.SkipTest('OpenSSL needed for synthetic certificate')
            subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3;context.load_cert_chain(cert,key)
            # Deliberately leave TLS session tickets enabled to check leftover
            # authenticated records at the v2 switch boundary.
            # sing-box 1.14.3's v2 client forwards leftover ticket bytes as
            # Shadowsocks data. Its server fixture therefore disables tickets;
            # our client is separately exercised with tickets enabled above.
            if project_server and version==2:context.num_tickets=0
            backend=socket.socket();backend.bind(('127.0.0.1',0));backend.listen();backend.settimeout(.2);backend_port=backend.getsockname()[1];stop=threading.Event();workers=[]
            def handle(raw):
                try:
                    with raw:
                        raw.settimeout(3)
                        with context.wrap_socket(raw,server_side=True) as tls:
                            tls.recv(65535)
                except OSError:pass
            def accept():
                while not stop.is_set():
                    try:c,_=backend.accept()
                    except OSError:continue
                    w=threading.Thread(target=handle,args=(c,));workers.append(w);w.start()
            listener=threading.Thread(target=accept);listener.start()
            ss_password=secret(method) if method.startswith('2022-') else 'ss-auth'
            if project_server:
                project={'outbounds':[{'tag':'direct','uri':'direct://'}],'final':'direct','inbounds':[{'protocol':'shadowtls','listen':f'127.0.0.1:{server}','password':'shadow-auth','cipher':method,'options':{'version':str(version),'handshake':f'127.0.0.1:{backend_port}','ss-password':ss_password,'uot':'2'}}]}
                reference={'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks}],'outbounds':[{'type':'shadowsocks','tag':'ss','server':'127.0.0.1','server_port':server,'method':method,'password':ss_password,'detour':'shadow','udp_over_tcp':{'enabled':True,'version':2}},{'type':'shadowtls','tag':'shadow','server':'127.0.0.1','server_port':server,'version':version,'password':'shadow-auth','tls':{'enabled':True,'server_name':'localhost','certificate_path':str(cert)}}]}
            else:
                inbound={'type':'shadowtls','tag':'shadow','listen':'127.0.0.1','listen_port':server,'version':version,'handshake':{'server':'127.0.0.1','server_port':backend_port},'detour':'ss'}
                if version==3:inbound['users']=[{'password':'shadow-auth'}];inbound['strict_mode']=True
                else:inbound['password']='shadow-auth'
                reference={'inbounds':[inbound,{'type':'shadowsocks','tag':'ss','listen':'127.0.0.1','listen_port':ss,'method':method,'password':ss_password}],'outbounds':[{'type':'direct'}]}
                if plugin:
                    uri=f'ss://{method}:{quote(ss_password,safe='')}@127.0.0.1:{server}?plugin='+quote(f'shadow-tls;version={version};password=shadow-auth;host=localhost;uot=2;pinsha256={pin}',safe='')
                else:uri=f'shadowtls://shadow-auth@127.0.0.1:{server}?version={version}&method={method}&ss-password={quote(ss_password,safe='')}&uot=2&sni=localhost&pinsha256={pin}'
                project={'listen_port':socks,'outbounds':[{'tag':'shadow','uri':uri}],'final':'shadow'}
            pp,rp=root/'project.json',root/'reference.json';pp.write_text(json.dumps(project),encoding='utf-8');rp.write_text(json.dumps(reference),encoding='utf-8');processes=[]
            with (root/'project.log').open('w') as plog,(root/'reference.log').open('w') as rlog:
                try:
                    commands=[([str(BIN),'--config',str(pp)]+(['--no-socks'] if project_server else []),plog),([str(self.reference),'run','-c',str(rp)],rlog)]
                    for args,log in commands:processes.append(subprocess.Popen(args,stdout=log,stderr=log))
                    deadline=time.monotonic()+6
                    while True:
                        if any(p.poll() is not None for p in processes):self.fail('ShadowTLS process stopped before readiness')
                        try:
                            # The project SOCKS listener starts before its remote
                            # reference server. Check both endpoints before the
                            # first payload; do not retry delivered application data.
                            for ready_port in (socks,server):
                                with socket.create_connection(('127.0.0.1',ready_port),.2):pass
                            break
                        except OSError:
                            if time.monotonic()>deadline:self.fail('ShadowTLS readiness timeout')
                            time.sleep(.03)
                    yield socks
                except BaseException as error:
                    plog.flush();rlog.flush();error.add_note((root/'project.log').read_text(errors='replace')[-3000:]);error.add_note((root/'reference.log').read_text(errors='replace')[-3000:]);raise
                finally:
                    for p in reversed(processes):
                        if p.poll() is None:p.terminate()
                        try:p.wait(timeout=5)
                        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
                    stop.set();listener.join(timeout=2)
                    for w in workers:w.join(timeout=4);self.assertFalse(w.is_alive())
                    backend.close();self.assertFalse(listener.is_alive())
    def test_reference_tcp_udp_versions_directions_and_ss_plugin(self):
        self.payload_cases()
    def test_reference_embedded_ss2022_versions_directions_and_plugin(self):
        for method in ['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305']:
            with self.subTest(method=method):self.payload_cases(method)
    def payload_cases(self,method='aes-256-gcm'):
        for project_server,plugin in [(False,False),(False,True),(True,False)]:
            for version in [2,3]:
                with self.subTest(project_server=project_server,version=version,plugin=plugin),socket.socket() as tcp,socket.socket(type=socket.SOCK_DGRAM) as udp:
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
                        with self.pair(project_server,version,plugin,method) as socks:
                            for cycle in range(64 if version==2 and not project_server else 8):
                                c,_=self.socks(socks,1,tcp.getsockname())
                                with c:
                                    body=b'ShadowTLS independent payload\x00\xff'*256;c.sendall(body);self.assertEqual(exact(c,len(body)),body)
                            control,relay=self.socks(socks,3,('0.0.0.0',0))
                            with control,socket.socket(type=socket.SOCK_DGRAM) as client:
                                client.bind(('127.0.0.1',0));client.settimeout(5);header=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+udp.getsockname()[1].to_bytes(2,'big')
                                for size in [32,1400,3800]:
                                    body=b's'*size;client.sendto(header+body,relay);r,_=client.recvfrom(65535);self.assertEqual(r[10:],body)
                    finally:
                        stop.set()
                        for w in listeners:w.join(timeout=2);self.assertFalse(w.is_alive())
                        for w in workers:w.join(timeout=5);self.assertFalse(w.is_alive())
