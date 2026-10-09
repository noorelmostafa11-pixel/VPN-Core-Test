"""Independent wire tests for REALITY upgrade authority and TLS half closure.

Only a component probe is compiled; neither the core executable nor a package
is built here. Python/OpenSSL and the independent REALITY peer produce and
validate the remote TLS/HTTP records. Native Windows Schannel needs an OS-trusted
certificate, so its synthetic-certificate wire cases remain Linux-only.
"""
import base64
import datetime
import ipaddress
import os
import pathlib
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import test_expanded as peers
import test_reality as reality

ROOT=pathlib.Path(__file__).resolve().parents[1]
FINAL=b'authenticated final payload|'*2048

class MemoryTLSPeer:
    def __init__(self,cert,key,version,mode):
        self.mode=mode
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version=self.context.maximum_version=version
        self.context.load_cert_chain(cert,key)
        self.listener=socket.socket()
        self.listener.bind(('127.0.0.1',0));self.listener.listen(1)
        self.listener.settimeout(12)
        self.port=self.listener.getsockname()[1]
        self.received=bytearray();self.errors=[];self.peer_eof=False
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()

    def run(self):
        try:
            with self.listener.accept()[0] as raw:
                raw.settimeout(10)
                incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
                tls=self.context.wrap_bio(incoming,outgoing,server_side=True)
                def flush():
                    wire=outgoing.read()
                    if wire:raw.sendall(wire)
                def receive():
                    wire=raw.recv(65536)
                    if wire:incoming.write(wire)
                    else:incoming.write_eof()
                while True:
                    try:tls.do_handshake();flush();break
                    except ssl.SSLWantReadError:flush();receive()
                def read_to_close():
                    while True:
                        try:
                            data=tls.read(65536)
                            if not data:self.peer_eof=True;return
                            self.received.extend(data)
                        except ssl.SSLWantReadError:flush();receive()
                        except ssl.SSLZeroReturnError:self.peer_eof=True;return
                def send_final_and_close():
                    if self.mode=='websocket-close':
                        def frame(opcode,data):return bytes([opcode,126])+struct.pack('!H',len(data))+data if len(data)>=126 else bytes([opcode,len(data)])+data
                        data=frame(2,FINAL[:20000])+frame(0x89,b'end')+frame(0x80,FINAL[20000:])+frame(0x88,b'\x03\xe8')
                    else:data=FINAL
                    tls.write(data)
                    try:tls.unwrap()
                    except ssl.SSLWantReadError:pass
                    flush()
                if self.mode in ('peer-close','websocket-close'):
                    # Coalesce multiple application records and close_notify.
                    send_final_and_close();read_to_close()
                elif self.mode=='local-close':
                    if self.context.maximum_version==ssl.TLSVersion.TLSv1_2:
                        # Already pending data precedes TLS 1.2's reciprocal
                        # close; no new application write follows peer closure.
                        tls.write(FINAL);flush();read_to_close()
                        try:tls.unwrap()
                        except ssl.SSLWantReadError:pass
                        flush();return
                    read_to_close()
                    # Its sending direction remains open in TLS 1.3.
                    send_final_and_close()
                elif self.mode=='bad-record':
                    tls.write(b'authenticated record that will be corrupted')
                    wire=bytearray(outgoing.read());wire[-1]^=1;raw.sendall(wire)
                    # A fatal alert or TCP teardown is expected, never app data.
                    try:read_to_close()
                    except (ssl.SSLError,ConnectionResetError,BrokenPipeError):pass
                else:raise ValueError('unknown fixture mode')
        except Exception as error:self.errors.append(repr(error))
        finally:self.listener.close()

    def finish(self):
        self.thread.join(12)
        if self.thread.is_alive():
            self.listener.close()
            raise AssertionError('independent TLS peer did not finish')

class TLSWriteStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='tls-state-component-')
        cls.directory=pathlib.Path(cls.temp.name)
        provided=os.environ.get('VPN_CORE_TLS_WRITE_PROBE')
        cls.probe=pathlib.Path(provided) if provided else cls.directory/('tls-write-probe.exe' if os.name=='nt' else 'tls-write-probe')
        if not provided:
            provider='vpn-tls.dll' if os.name=='nt' else 'libvpn-tls.so'
            shutil.copy2(ROOT/'bin'/provider,cls.directory/provider)
            compiler=os.environ.get('CXX','g++')
            flags=['-std=c++17','-O2','-Wall','-Wextra','-Wpedantic','-Werror','-Wno-misleading-indentation']
            if os.name=='nt':flags+=['-D_WIN32_WINNT=0x0A00','-static','-static-libgcc','-static-libstdc++'];libraries=['-lws2_32','-lsecur32','-lcrypt32','-lbcrypt','-pthread']
            else:flags+=['-DVPN_CORE_TEST_BACKEND'];libraries=['-lssl','-lcrypto','-ldl','-pthread']
            subprocess.run([compiler,*flags,str(ROOT/'tests/tls_write_probe.cpp'),'-o',str(cls.probe),*libraries],check=True,timeout=120)
        cls.key=cls.directory/'key.pem';cls.cert=cls.directory/'cert.pem'
        key=ec.generate_private_key(ec.SECP256R1())
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        now=datetime.datetime.now(datetime.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(43).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
            .sign(key,hashes.SHA256()))
        cls.key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
        cls.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def probe_run(self,mode,input):
        return subprocess.run([str(self.probe),mode,str(input)],capture_output=True,text=True,timeout=15)

    def closure_case(self,mode,version,backend):
        peer=MemoryTLSPeer(self.cert,self.key,version,'local-close' if mode=='direct-api-close' else mode)
        config=self.directory/'probe.cfg'
        config.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&type='+('websocket' if mode=='websocket-close' else 'tcp')+'&sni=localhost'+('&fp=native' if backend=='provider' else '')+'\n'+('tls_ca_file=' if backend=='provider' or os.name=='nt' else 'test_ca_file=')+str(self.cert)+'\n')
        result=self.probe_run(mode,config);peer.finish()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('PASS:',result.stdout)
        self.assertEqual(peer.errors,[])
        expected=b'required final control' if mode=='peer-close' and version==ssl.TLSVersion.TLSv1_3 else b''
        if mode=='websocket-close' and version==ssl.TLSVersion.TLSv1_3:
            data=bytes(peer.received);frames=[]
            while data:
                self.assertGreaterEqual(len(data),6)
                self.assertTrue(data[1]&128)
                n=data[1]&127;self.assertLess(n,126)
                self.assertGreaterEqual(len(data),6+n)
                mask=data[2:6];body=bytes(value^mask[index%4] for index,value in enumerate(data[6:6+n]))
                frames.append((data[0],body));data=data[6+n:]
            self.assertEqual(frames,[(0x8a,b'end'),(0x88,b'\x03\xe8')])
        else:self.assertEqual(bytes(peer.received),expected)
        if mode!='bad-record':self.assertTrue(peer.peer_eof)

    def test_tls13_peer_close_keeps_final_data_and_required_write(self):
        for backend in ('provider','native') if os.name!='nt' else ('provider',):
            with self.subTest(backend=backend):self.closure_case('peer-close',ssl.TLSVersion.TLSv1_3,backend)

    def test_tls13_local_close_rejects_write_and_preserves_read(self):
        for backend in ('provider','native') if os.name!='nt' else ('provider',):
            with self.subTest(backend=backend):self.closure_case('local-close',ssl.TLSVersion.TLSv1_3,backend)

    def test_provider_c_abi_local_close_rejects_write_without_poisoning_read(self):
        self.closure_case('direct-api-close',ssl.TLSVersion.TLSv1_3,'provider')

    def test_tls12_peer_close_keeps_final_data_but_rejects_write(self):
        for backend in ('provider','native') if os.name!='nt' else ('provider',):
            with self.subTest(backend=backend):self.closure_case('peer-close',ssl.TLSVersion.TLSv1_2,backend)

    def test_tls12_local_close_rejects_write_without_losing_pending_read(self):
        for backend in ('provider','native') if os.name!='nt' else ('provider',):
            with self.subTest(backend=backend):self.closure_case('local-close',ssl.TLSVersion.TLSv1_2,backend)

    def test_tls13_websocket_close_keeps_final_fragments_and_control_frames(self):
        for backend in ('provider','native') if os.name!='nt' else ('provider',):
            with self.subTest(backend=backend):self.closure_case('websocket-close',ssl.TLSVersion.TLSv1_3,backend)

    def test_tls12_websocket_close_keeps_final_fragments_without_late_write(self):
        for backend in ('provider','native') if os.name!='nt' else ('provider',):
            with self.subTest(backend=backend):self.closure_case('websocket-close',ssl.TLSVersion.TLSv1_2,backend)

    def test_tls_errors_permanently_reject_writes(self):
        for version in (ssl.TLSVersion.TLSv1_3,ssl.TLSVersion.TLSv1_2):
            for backend in ('provider','native') if os.name!='nt' else ('provider',):
                with self.subTest(version=version,backend=backend):self.closure_case('bad-record',version,backend)

    def reality_case(self,transport,host=None,sni='localhost',expected='localhost',corrupt=False,reject=False):
        original=reality.TLS13Peer
        observed=[]
        class HeaderTap:
            def __init__(self,sock):self.sock=sock;self.header=bytearray();self.done=False
            def recv(self,n):
                data=self.sock.recv(n)
                if not self.done:
                    self.header.extend(data)
                    if self.header.endswith(b'\r\n\r\n'):
                        self.done=True
                        value=next(line.split(':',1)[1].strip() for line in self.header.decode().split('\r\n') if line.lower().startswith('host:'))
                        observed.append(value)
                        if value!=expected:
                            self.sock.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
                            raise EOFError('independent virtual host rejected')
                return data
            def __getattr__(self,name):return getattr(self.sock,name)
        class UpgradeWire(peers.Wrapped):
            def close(self):self.sock.close()
        def wrapped(*args,**kwargs):return UpgradeWire(HeaderTap(original(*args,**kwargs)),transport)
        reality.TLS13Peer=wrapped
        try:
            peer=reality.RealityPeer(corrupt=corrupt)
            try:
                uri=reality.RealityTests.uri(peer).replace('type=tcp','type='+transport).replace('sni=localhost','sni='+sni)+'&path=/test'
                if host is not None:uri+='&host='+host
                result=self.probe_run('upgrade',uri)
                self.assertEqual(result.returncode,1 if corrupt or reject else 0,result.stderr)
                if corrupt:
                    self.assertIn('REALITY_AUTHENTICATION',result.stderr);self.assertEqual(observed,[])
                else:
                    self.assertEqual(observed,[host or expected]);self.assertEqual(peer.authenticated,1)
                    if reject:self.assertIn('HTTP_UPGRADE_STATUS',result.stderr)
                    else:self.assertIn('PASS:',result.stdout)
                self.assertEqual(peer.errors,[])
            finally:peer.close()
        finally:reality.TLS13Peer=original

    def test_reality_upgrade_uses_sni_and_preserves_explicit_host(self):
        for transport in ('websocket','httpupgrade'):
            for host,expected in ((None,'localhost'),('','localhost'),('explicit.example.test','explicit.example.test')):
                with self.subTest(transport=transport,host=host):self.reality_case(transport,host=host,expected=expected)

    def test_reality_upgrade_empty_sni_uses_endpoint_without_port(self):
        for transport in ('websocket','httpupgrade'):
            with self.subTest(transport=transport):self.reality_case(transport,sni='',expected='127.0.0.1')

    def test_reality_upgrade_authentication_and_wrong_host_still_rejected(self):
        for transport in ('websocket','httpupgrade'):
            with self.subTest(transport=transport,control='authentication'):self.reality_case(transport,corrupt=True)
            with self.subTest(transport=transport,control='virtual_host'):self.reality_case(transport,host='wrong.example.test',reject=True)

    def test_reality_upgrade_does_not_admit_vision_carriers(self):
        public=base64.urlsafe_b64encode(bytes(32)).decode().rstrip('=')
        for transport in ('websocket','httpupgrade'):
            result=self.probe_run('host',f'vless://{peers.ID}@127.0.0.1:9?security=reality&type={transport}&sni=localhost&fp=chrome&pbk={public}&sid=a1b2c3d4&flow=xtls-rprx-vision')
            self.assertEqual(result.returncode,1)
            self.assertIn('VISION_CONFIGURATION',result.stderr)

if __name__=='__main__':unittest.main()
