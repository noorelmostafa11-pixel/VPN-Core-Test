"""Official AnyTLS 0.0.13 binaries are test-only; runtime imports no GPL engine."""
import contextlib
import hashlib
import json
import os
import pathlib
import socket
import ssl
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from test_core import BIN, exact, free_port
import test_hysteria_reference as hyref
from cryptography import x509


class AnyTLSReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = pathlib.Path(os.environ.get('VPN_CORE_REFERENCE_ANYTLS', ''))
        cls.server_exe = cls.reference / 'anytls-server.exe'
        if not cls.server_exe.is_file():
            raise unittest.SkipTest('set VPN_CORE_REFERENCE_ANYTLS to official 0.0.13 binary directory')

    def socks(self, *args):
        return hyref.HysteriaReferenceTests.socks(self, *args)

    @contextlib.contextmanager
    def project_server_pair(self):
        with tempfile.TemporaryDirectory(prefix='vpn-anytls-server-reference-') as temp:
            root=pathlib.Path(temp);cert,key=root/'cert.pem',root/'key.pem'
            openssl=shutil.which('openssl')
            if not openssl and os.name=='nt':
                path=pathlib.Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Git/usr/bin/openssl.exe'
                if path.is_file():openssl=str(path)
            if not openssl:raise unittest.SkipTest('OpenSSL needed for synthetic reference certificate')
            subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            server,socks=free_port(),free_port()
            spec={'protocol':'anytls','listen':f'127.0.0.1:{server}','password':'synthetic-auth','cert_file':str(cert),'key_file':str(key),'options':{'padding-scheme':'stop=3\n0=40-50\n1=180-240\n2=800-900,c,900-1000'}}
            profile={'outbounds':[{'tag':'direct','uri':'direct://'}],'final':'direct','inbounds':[spec]}
            config=root/'server.json';config.write_text(json.dumps(profile),encoding='utf-8')
            with (root/'project.log').open('w') as plog,(root/'reference.log').open('w') as rlog:
                processes=[]
                try:
                    project=subprocess.Popen([str(BIN),'--config',str(config),'--no-socks'],stdout=plog,stderr=plog);processes.append(project)
                    reference=subprocess.Popen([str(self.reference/'anytls-client.exe'),'-l',f'127.0.0.1:{socks}','-s',f'127.0.0.1:{server}','-p','synthetic-auth','-sni','localhost'],stdout=rlog,stderr=rlog);processes.append(reference)
                    deadline=time.monotonic()+6
                    while True:
                        if any(p.poll() is not None for p in processes):self.fail('AnyTLS process stopped before readiness')
                        try:
                            with socket.create_connection(('127.0.0.1',socks),.2):break
                        except OSError:
                            if time.monotonic()>deadline:self.fail('AnyTLS listener readiness timeout')
                            time.sleep(.03)
                    yield socks
                except BaseException as error:
                    plog.flush();rlog.flush();error.add_note((root/'project.log').read_text(errors='replace')[-3000:]);error.add_note((root/'reference.log').read_text(errors='replace')[-3000:]);raise
                finally:
                    for p in reversed(processes):
                        if p.poll() is None:p.terminate()
                        try:p.wait(timeout=5)
                        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)

    @contextlib.contextmanager
    def pair(self, padding='', bad_auth=False):
        server_port, socks_port = free_port(), free_port()
        with tempfile.TemporaryDirectory(prefix='vpn-anytls-reference-') as temp:
            root = pathlib.Path(temp)
            with (root / 'reference.log').open('w') as rlog, (root / 'project.log').open('w') as plog:
                processes = []
                try:
                    args = [str(self.server_exe), '-l', f'127.0.0.1:{server_port}', '-p', 'synthetic-auth']
                    if padding:
                        padding_file=root/'padding.txt';padding_file.write_text(padding,encoding='utf-8');args += ['-padding-scheme',str(padding_file)]
                    other = subprocess.Popen(args, stdout=rlog, stderr=rlog); processes.append(other)
                    deadline = time.monotonic() + 6
                    while True:
                        if other.poll() is not None: self.fail('reference stopped before readiness')
                        try:
                            # Observe only the generated loopback test certificate,
                            # then pin that exact DER on the verified core connection.
                            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
                            with socket.create_connection(('127.0.0.1', server_port), .2) as raw:
                                with context.wrap_socket(raw, server_hostname='localhost') as tls:
                                    der=tls.getpeercert(binary_form=True);pin = hashlib.sha256(der).hexdigest()
                                    certificate=x509.load_der_x509_certificate(der)
                                    names=certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                                    name=names[0]
                            break
                        except OSError:
                            if time.monotonic() > deadline: self.fail('reference readiness timeout')
                            time.sleep(.03)
                    uri = f'anytls://{"wrong" if bad_auth else "synthetic-auth"}@127.0.0.1:{server_port}?pinsha256={pin}&sni={name}'
                    config = {'listen_port': socks_port, 'outbounds': [{'tag': 'any', 'uri': uri}], 'final': 'any'}
                    path = root / 'project.json'; path.write_text(json.dumps(config), encoding='utf-8')
                    project = subprocess.Popen([str(BIN), '--config', str(path)], stdout=plog, stderr=plog); processes.append(project)
                    while True:
                        if project.poll() is not None: self.fail('project stopped before readiness')
                        try:
                            with socket.create_connection(('127.0.0.1', socks_port), .2): break
                        except OSError:
                            if time.monotonic() > deadline: self.fail('project readiness timeout')
                            time.sleep(.03)
                    yield socks_port
                except BaseException as error:
                    rlog.flush(); plog.flush()
                    error.add_note((root / 'reference.log').read_text(errors='replace')[-3000:])
                    error.add_note((root / 'project.log').read_text(errors='replace')[-3000:]); raise
                finally:
                    for p in reversed(processes):
                        if p.poll() is None: p.terminate()
                        try: p.wait(timeout=5)
                        except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=3)

    def test_official_server_tcp_payload_and_padding_update(self):
        for padding in ['', 'stop=3\n0=40-50\n1=180-240\n2=800-900,c,900-1000']:
            with self.subTest(updated=bool(padding)), socket.socket() as echo:
                echo.bind(('127.0.0.1', 0)); echo.listen(); echo.settimeout(.2)
                stop = threading.Event(); workers = []
                def handle(c):
                    try:
                        with c:
                            c.settimeout(3)
                            while data := c.recv(65535): c.sendall(data)
                    except OSError: pass
                def accept():
                    while not stop.is_set():
                        try: c, _ = echo.accept()
                        except (TimeoutError, OSError): continue
                        w = threading.Thread(target=handle, args=(c,)); workers.append(w); w.start()
                thread = threading.Thread(target=accept); thread.start()
                try:
                    with self.pair(padding) as socks:
                        for cycle in range(16):
                            c, _ = self.socks(socks, 1, echo.getsockname())
                            with c:
                                body = b'AnyTLS independent bidirectional payload\x00\xff' * 128
                                c.sendall(body); self.assertEqual(exact(c, len(body)), body)
                finally:
                    stop.set(); thread.join(timeout=2)
                    for w in workers: w.join(timeout=4); self.assertFalse(w.is_alive())
                    self.assertFalse(thread.is_alive())

    def test_official_client_server_tcp_and_udp_both_directions(self):
        for project_server in [False,True]:
            with self.subTest(project_server=project_server),socket.socket() as tcp,socket.socket(type=socket.SOCK_DGRAM) as udp:
                tcp.bind(('127.0.0.1',0));tcp.listen();tcp.settimeout(.2);udp.bind(('127.0.0.1',0));udp.settimeout(.2)
                stop=threading.Event();workers=[]
                def handle(c):
                    try:
                        with c:
                            c.settimeout(3)
                            while data:=c.recv(65535):c.sendall(data)
                    except OSError:pass
                def accept():
                    while not stop.is_set():
                        try:c,_=tcp.accept()
                        except (TimeoutError,OSError):continue
                        w=threading.Thread(target=handle,args=(c,));workers.append(w);w.start()
                def echo_udp():
                    while not stop.is_set():
                        try:body,a=udp.recvfrom(65535);udp.sendto(body,a)
                        except (TimeoutError,OSError):continue
                listeners=[threading.Thread(target=accept),threading.Thread(target=echo_udp)]
                for w in listeners:w.start()
                try:
                    pair=self.project_server_pair() if project_server else self.pair()
                    with pair as socks:
                        for i in range(8):
                            c,_=self.socks(socks,1,tcp.getsockname())
                            with c:
                                body=b'AnyTLS official TCP and UDP\x00\xff'*128;c.sendall(body);self.assertEqual(exact(c,len(body)),body)
                        control,relay=self.socks(socks,3,('0.0.0.0',0))
                        with control,socket.socket(type=socket.SOCK_DGRAM) as client:
                            client.bind(('127.0.0.1',0));client.settimeout(5)
                            header=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+udp.getsockname()[1].to_bytes(2,'big')
                            for size in [32,1400,3800]:
                                body=b'y'*size;client.sendto(header+body,relay);r,_=client.recvfrom(65535);self.assertEqual(r[10:],body)
                finally:
                    stop.set()
                    for w in listeners:w.join(timeout=2);self.assertFalse(w.is_alive())
                    for w in workers:w.join(timeout=4);self.assertFalse(w.is_alive())
