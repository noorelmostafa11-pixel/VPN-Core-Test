"""Independent Xray client against project Go server inbounds, on loopback only."""
import contextlib
import concurrent.futures
import base64
import hashlib
import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from cryptography.hazmat.primitives.asymmetric import x25519
import test_hysteria_reference as hyref
from test_core import BIN, exact, free_port

UUID = '12345678-1234-4567-9234-567812345678'
PASSWORD = 'synthetic-reference-server-password'


class ServerReferenceTests(unittest.TestCase):
    def socks(self, *args):
        return hyref.HysteriaReferenceTests.socks(self, *args)
    @classmethod
    def setUpClass(cls):
        candidate = os.environ.get('VPN_CORE_REFERENCE_XRAY', '')
        if not candidate or not pathlib.Path(candidate).is_file():
            raise unittest.SkipTest('set VPN_CORE_REFERENCE_XRAY to an independently installed Xray executable')
        cls.xray = pathlib.Path(candidate)
        cls.reference_version = subprocess.check_output([str(cls.xray), 'version'], text=True).splitlines()[0]
        cls.temp = tempfile.TemporaryDirectory(prefix='vpn-server-reference-')
        cls.root = pathlib.Path(cls.temp.name)
        openssl = shutil.which('openssl')
        if not openssl and os.name == 'nt':
            candidate = pathlib.Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/usr/bin/openssl.exe'
            if candidate.exists():
                openssl = str(candidate)
        if not openssl:
            cls.temp.cleanup()
            raise unittest.SkipTest('OpenSSL is needed only to create the synthetic test certificate')
        cls.cert, cls.key = cls.root / 'cert.pem', cls.root / 'key.pem'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-keyout', str(cls.key), '-out', str(cls.cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def wait_port(self, process, port):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail('reference or project core stopped before readiness')
            try:
                with socket.create_connection(('127.0.0.1', port), .2):
                    return
            except OSError:
                time.sleep(.03)
        self.fail('listener did not become ready')

    @contextlib.contextmanager
    def reference_pair(self, protocol, cipher='aes-256-gcm', wrong_password=False, secure=False,
                       alter_id=0, authenticated_length=False, mux=False, legacy=None, flow='', server_flow=None, reality=None, fingerprint='chrome', decryption=None, encryption=None, transport=None, grpc_multi=False):
        server_port, socks_port = free_port(), free_port()
        spec = {'protocol': protocol, 'listen': f'127.0.0.1:{server_port}'}
        if protocol == 'vmess':
            spec['uuids'] = [UUID]
            if alter_id:
                spec['options'] = {'alter-id': str(alter_id)}
            identity = 'abcdefab-1234-4567-9234-567812345678' if wrong_password else UUID
            settings = {'vnext': [{'address': '127.0.0.1', 'port': server_port,
                                  'users': [{'id': identity, 'security': cipher, 'alterId': alter_id,
                                             'experiments': 'AuthenticatedLength' if authenticated_length else ''}]}]}
        elif protocol == 'vless':
            spec['uuids'] = [UUID]
            configured_flow = flow if server_flow is None else server_flow
            if configured_flow:
                spec['options'] = {'flow': configured_flow}
            if decryption:
                spec.setdefault('options', {})['decryption'] = decryption
            settings = {'vnext': [{'address': '127.0.0.1', 'port': server_port,
                                  'users': [{'id': UUID, 'encryption': encryption or 'none', 'flow': flow}]}]}
        else:
            spec['password'] = PASSWORD
            remote = {'address': '127.0.0.1', 'port': server_port,
                      'password': PASSWORD + ('-incorrect' if wrong_password else '')}
            if protocol == 'ss':
                spec['cipher'], remote['method'] = cipher, cipher
            settings = {'servers': [remote]}
        outbound = {'protocol': 'shadowsocks' if protocol == 'ss' else protocol, 'settings': settings}
        if reality:
            spec['reality'] = reality
            private = x25519.X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(reality['private_key'] + '=' * (-len(reality['private_key']) % 4)))
            public = base64.urlsafe_b64encode(private.public_key().public_bytes_raw()).decode().rstrip('=')
            outbound['streamSettings'] = {'security': 'reality', 'realitySettings': {
                'serverName': 'localhost', 'fingerprint': fingerprint, 'publicKey': public, 'shortId': 'a1b2c3d4'}}
        if mux:
            outbound['mux'] = {'enabled': True, 'concurrency': 8}
        if (protocol == 'trojan' or secure) and not reality:
            spec.update(cert_file=str(self.cert), key_file=str(self.key))
            der = ssl.PEM_cert_to_DER_cert(self.cert.read_text(encoding='utf-8'))
            pin = hashlib.sha256(der).hexdigest()
            outbound['streamSettings'] = {'security': 'tls', 'tlsSettings': {
                'serverName': 'localhost', 'pinnedPeerCertSha256': pin, 'verifyPeerCertByName': 'localhost'}}
            if legacy:
                # V2Ray 4 predates Xray's pin fields. Trust only the generated
                # fixture CA while preserving normal certificate/name checks.
                outbound['streamSettings']['tlsSettings'] = {'serverName': 'localhost',
                    'disableSystemRoot': True, 'certificates': [{'certificateFile': str(self.cert), 'usage': 'verify'}]}
        if transport:
            spec['transport'] = transport
            if protocol == 'ss':
                spec.setdefault('options', {})['udp'] = 'false'
            stream = outbound.setdefault('streamSettings', {})
            stream['network'] = 'ws' if transport['type'] == 'websocket' else transport['type']
            if transport['type'] == 'websocket':
                stream['wsSettings'] = {'path': transport['path'], 'headers': {'Host': transport.get('host', 'localhost')}}
            elif transport['type'] == 'grpc':
                stream['grpcSettings'] = {'serviceName': transport.get('service', 'GunService'), 'multiMode': grpc_multi}
            elif transport['type'] == 'http2':
                stream['network'] = 'http'
                stream['httpSettings'] = {'path': transport.get('path', '/'), 'host': [transport.get('host', 'localhost')]}
                if transport.get('method'):
                    stream['httpSettings']['method'] = transport['method']
            else:
                stream['httpupgradeSettings'] = {'path': transport['path'], 'host': transport.get('host', 'localhost')}
        profile = {'outbounds': [{'tag': 'direct', 'uri': 'direct://'}], 'final': 'direct', 'inbounds': [spec]}
        reference = {'log': {'loglevel': 'warning'},
                     'inbounds': [{'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks', 'settings': {'udp': True}}],
                     'outbounds': [outbound]}
        with tempfile.TemporaryDirectory(dir=self.root) as temp:
            root = pathlib.Path(temp)
            project_file, reference_file = root / 'project.json', root / 'reference.json'
            project_file.write_text(json.dumps(profile), encoding='utf-8')
            reference_file.write_text(json.dumps(reference), encoding='utf-8')
            with (root / 'project.log').open('w', encoding='utf-8') as project_log, (root / 'reference.log').open('w', encoding='utf-8') as reference_log:
                processes = []
                try:
                    project = subprocess.Popen([str(BIN), '--config', str(project_file), '--no-socks'], stdout=project_log, stderr=project_log)
                    processes.append(project)
                    self.wait_port(project, server_port)
                    args = [str(legacy), '-config', str(reference_file)] if legacy else [str(self.xray), 'run', '-config', str(reference_file)]
                    other = subprocess.Popen(args, stdout=reference_log, stderr=reference_log)
                    processes.append(other)
                    self.wait_port(other, socks_port)
                    yield socks_port
                except BaseException as error:
                    project_log.flush()
                    reference_log.flush()
                    error.add_note((root / 'project.log').read_text(encoding='utf-8', errors='replace')[-4000:])
                    error.add_note((root / 'reference.log').read_text(encoding='utf-8', errors='replace')[-4000:])
                    raise
                finally:
                    for process in reversed(processes):
                        if process.poll() is None:
                            process.terminate()
                        try:
                            process.wait(timeout=8)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)

    def test_xray_clients_transfer_real_tcp_payload(self):
        for protocol, cipher in [('vless', ''), ('trojan', ''), ('ss', 'aes-256-gcm'), ('ss', 'chacha20-ietf-poly1305')]:
            with self.subTest(protocol=protocol, cipher=cipher):
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                listener.settimeout(8)
                def echo():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(8)
                            while data := connection.recv(4096):
                                connection.sendall(data)
                    except OSError:
                        pass
                worker = threading.Thread(target=echo)
                worker.start()
                try:
                    with self.reference_pair(protocol, cipher) as socks:
                        with socket.create_connection(('127.0.0.1', socks), 5) as connection:
                            connection.settimeout(5)
                            connection.sendall(b'\x05\x01\x00')
                            self.assertEqual(exact(connection, 2), b'\x05\x00')
                            destination = socket.inet_aton('127.0.0.1') + listener.getsockname()[1].to_bytes(2, 'big')
                            connection.sendall(b'\x05\x01\x00\x01' + destination)
                            reply = exact(connection, 4)
                            self.assertEqual(reply[:2], b'\x05\x00')
                            if reply[3] == 1:
                                exact(connection, 6)
                            elif reply[3] == 4:
                                exact(connection, 18)
                            else:
                                exact(connection, exact(connection, 1)[0] + 2)
                            payload = (b'independent Xray client verified\x00\xff' * 128)
                            connection.sendall(payload)
                            self.assertEqual(exact(connection, len(payload)), payload)
                finally:
                    listener.close()
                    worker.join(timeout=10)
                    self.assertFalse(worker.is_alive(), 'independent echo worker did not stop')

    def test_xray_vmess_tcp_udp_raw_and_tls(self):
        self.vmess_payload_cases()

    def test_xray_vmess_authenticated_length(self):
        self.vmess_payload_cases(authenticated_length=True)

    def test_v2ray_legacy_vmess_methods(self):
        legacy = os.environ.get('VPN_CORE_REFERENCE_V2RAY4', '')
        if not legacy or not pathlib.Path(legacy).is_file():
            self.skipTest('set VPN_CORE_REFERENCE_V2RAY4 to the official V2Ray 4.45.2 executable')
        self.assertIn('4.45.2', subprocess.check_output([legacy, '-version'], text=True))
        self.vmess_payload_cases(legacy=legacy, alter_id=2,
                                 methods=['aes-128-gcm', 'chacha20-poly1305', 'aes-128-cfb', 'none', 'zero'])

    def vmess_payload_cases(self, authenticated_length=False, legacy=None, alter_id=0, methods=None):
        for secure in [False, True]:
            for cipher in methods or ['aes-128-gcm', 'chacha20-poly1305']:
                with self.subTest(tls=secure, cipher=cipher):
                    tcp, udp = socket.socket(), socket.socket(type=socket.SOCK_DGRAM)
                    tcp.bind(('127.0.0.1', 0)); tcp.listen(); tcp.settimeout(.2)
                    udp.bind(('127.0.0.1', 0)); udp.settimeout(.2)
                    stop = threading.Event(); connections = []
                    def handle(c):
                        try:
                            with c:
                                c.settimeout(5)
                                while data := c.recv(65535):
                                    c.sendall(data)
                        except OSError:
                            pass
                    def accept():
                        while not stop.is_set():
                            try:
                                c, _ = tcp.accept()
                            except OSError:
                                continue
                            w = threading.Thread(target=handle, args=(c,)); connections.append(w); w.start()
                    def echo_udp():
                        while not stop.is_set():
                            try:
                                data, addr = udp.recvfrom(65535); udp.sendto(data, addr)
                            except OSError:
                                continue
                    workers = [threading.Thread(target=accept), threading.Thread(target=echo_udp)]
                    for w in workers: w.start()
                    try:
                        with self.reference_pair('vmess', cipher, secure=secure, authenticated_length=authenticated_length,
                                                 legacy=legacy, alter_id=alter_id) as socks:
                            for cycle in range(16):
                                c, _ = self.socks(socks, 1, tcp.getsockname())
                                with c:
                                    body = b'VMess independent Xray response\x00\xff' * 256
                                    c.sendall(body); self.assertEqual(exact(c, len(body)), body)
                            # Zero denotes unframed TCP; legacy V2Ray itself does
                            # not support packet framing for that security mode.
                            for cycle in range(0 if cipher == 'zero' else 32):
                                control, relay = self.socks(socks, 3, ('0.0.0.0', 0))
                                with control, socket.socket(type=socket.SOCK_DGRAM) as client:
                                    client.bind(('127.0.0.1', 0)); client.settimeout(5)
                                    header = b'\0\0\0\1' + socket.inet_aton('127.0.0.1') + udp.getsockname()[1].to_bytes(2, 'big')
                                    # V2Ray 4.45.2 uses a 2 KiB packet buffer;
                                    # larger project packets are tested in Go.
                                    for size in ([32, 1400, 1800] if legacy else [32, 1400, 3800]):
                                        body = b'z' * size; client.sendto(header + body, relay)
                                        try:
                                            response, _ = client.recvfrom(65535)
                                            self.assertEqual(response[10:], body)
                                        except BaseException as error:
                                            error.add_note(f'UDP association {cycle}, payload {size}, tls={secure}, cipher={cipher}')
                                            raise
                    finally:
                        stop.set(); tcp.close(); udp.close()
                        for w in workers + connections:
                            w.join(timeout=6); self.assertFalse(w.is_alive())

    def test_xray_vmess_mux_concurrent_tcp(self):
        self.mux_tcp_payload('vmess', ['aes-128-gcm', 'chacha20-poly1305'])

    def test_xray_vless_mux_concurrent_tcp(self):
        self.mux_tcp_payload('vless', [''])

    def mux_tcp_payload(self, protocol, methods):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(.2)
        stop, connections = threading.Event(), []
        def echo(c):
            try:
                with c:
                    c.settimeout(8)
                    while data := c.recv(65535): c.sendall(data)
            except OSError:
                pass
        def accept():
            while not stop.is_set():
                try: c, _ = listener.accept()
                except OSError: continue
                w = threading.Thread(target=echo, args=(c,)); connections.append(w); w.start()
        worker = threading.Thread(target=accept); worker.start()
        try:
            for cipher in methods:
                with self.subTest(protocol=protocol, cipher=cipher), self.reference_pair(protocol, cipher, secure=True, mux=True) as socks:
                    def transfer(i):
                        c, _ = self.socks(socks, 1, listener.getsockname())
                        with c:
                            c.settimeout(8)
                            body = bytes([i]) * 200001
                            c.sendall(body)
                            self.assertEqual(exact(c, len(body)), body)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                        for batch in range(4):
                            list(pool.map(transfer, range(8)))
        finally:
            stop.set(); listener.close()
            for w in [worker, *connections]:
                w.join(timeout=10); self.assertFalse(w.is_alive())
