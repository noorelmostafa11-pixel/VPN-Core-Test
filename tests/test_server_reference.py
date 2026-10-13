"""Independent Xray client against project Go server inbounds, on loopback only."""
import contextlib
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
from test_core import BIN, exact, free_port

UUID = '12345678-1234-4567-9234-567812345678'
PASSWORD = 'synthetic-reference-server-password'


class ServerReferenceTests(unittest.TestCase):
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
    def reference_pair(self, protocol, cipher='aes-256-gcm', wrong_password=False):
        server_port, socks_port = free_port(), free_port()
        spec = {'protocol': protocol, 'listen': f'127.0.0.1:{server_port}'}
        if protocol == 'vless':
            spec['uuids'] = [UUID]
            settings = {'vnext': [{'address': '127.0.0.1', 'port': server_port,
                                  'users': [{'id': UUID, 'encryption': 'none'}]}]}
        else:
            spec['password'] = PASSWORD
            remote = {'address': '127.0.0.1', 'port': server_port,
                      'password': PASSWORD + ('-incorrect' if wrong_password else '')}
            if protocol == 'ss':
                spec['cipher'], remote['method'] = cipher, cipher
            settings = {'servers': [remote]}
        outbound = {'protocol': 'shadowsocks' if protocol == 'ss' else protocol, 'settings': settings}
        if protocol == 'trojan':
            spec.update(cert_file=str(self.cert), key_file=str(self.key))
            der = ssl.PEM_cert_to_DER_cert(self.cert.read_text(encoding='utf-8'))
            pin = hashlib.sha256(der).hexdigest()
            outbound['streamSettings'] = {'security': 'tls', 'tlsSettings': {
                'serverName': 'localhost', 'pinnedPeerCertSha256': pin, 'verifyPeerCertByName': 'localhost'}}
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
                    other = subprocess.Popen([str(self.xray), 'run', '-config', str(reference_file)], stdout=reference_log, stderr=reference_log)
                    processes.append(other)
                    self.wait_port(other, socks_port)
                    yield socks_port
                except BaseException as error:
                    project_log.flush()
                    reference_log.flush()
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
