"""Official standalone Hysteria 2 executable in both directions, loopback only."""
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


class HysteriaReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = pathlib.Path(os.environ.get('VPN_CORE_REFERENCE_HYSTERIA', ''))
        if not cls.reference.is_file():
            raise unittest.SkipTest('set VPN_CORE_REFERENCE_HYSTERIA to the official standalone executable')
        cls.version = subprocess.check_output([str(cls.reference), 'version'], text=True)
        if 'v2.13.0' not in cls.version:
            raise unittest.SkipTest('this fixture pins official Hysteria 2.13.0')
        cls.temp = tempfile.TemporaryDirectory(prefix='vpn-hysteria-reference-')
        cls.root = pathlib.Path(cls.temp.name)
        openssl = shutil.which('openssl')
        if not openssl and os.name == 'nt':
            candidate = pathlib.Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/usr/bin/openssl.exe'
            if candidate.is_file():
                openssl = str(candidate)
        if not openssl:
            cls.temp.cleanup()
            raise unittest.SkipTest('OpenSSL is needed to generate the synthetic test certificate')
        cls.cert, cls.key = cls.root / 'cert.pem', cls.root / 'key.pem'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-keyout', str(cls.key), '-out', str(cls.cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cls.cert.read_text())).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextlib.contextmanager
    def pair(self, project_is_server, mode):
        server_port, socks_port = free_port(), free_port()
        options = {} if mode == 'none' else {'obfs': mode, 'obfs-password': 'synthetic-obfs-secret'}
        reference_obfs = {} if mode == 'none' else {
            'obfs': {'type': mode, mode: {'password': 'synthetic-obfs-secret'}}}
        if project_is_server:
            spec = {'protocol': 'hysteria2', 'listen': f'127.0.0.1:{server_port}',
                    'password': 'synthetic-auth', 'cert_file': str(self.cert),
                    'key_file': str(self.key), 'options': options}
            project = {'outbounds': [{'tag': 'direct', 'uri': 'direct://'}], 'final': 'direct', 'inbounds': [spec]}
            reference = {'server': f'127.0.0.1:{server_port}', 'auth': 'synthetic-auth',
                         'tls': {'sni': 'localhost', 'ca': str(self.cert)},
                         'socks5': {'listen': f'127.0.0.1:{socks_port}'}, **reference_obfs}
            project_args, reference_mode = ['--no-socks'], 'client'
        else:
            query = '&'.join(f'{k}={v}' for k, v in options.items())
            uri = f'hy2://synthetic-auth@127.0.0.1:{server_port}?sni=localhost&pinsha256={self.pin}&{query}'
            project = {'listen_port': socks_port, 'outbounds': [{'tag': 'hy', 'uri': uri}], 'final': 'hy'}
            reference = {'listen': f'127.0.0.1:{server_port}', 'tls': {'cert': str(self.cert), 'key': str(self.key)},
                         'auth': {'type': 'password', 'password': 'synthetic-auth'}, **reference_obfs}
            project_args, reference_mode = [], 'server'
        with tempfile.TemporaryDirectory(dir=self.root) as temp:
            root = pathlib.Path(temp)
            pfile, rfile = root / 'project.json', root / 'reference.json'
            pfile.write_text(json.dumps(project), encoding='utf-8')
            rfile.write_text(json.dumps(reference), encoding='utf-8')
            with (root / 'project.log').open('w') as plog, (root / 'reference.log').open('w') as rlog:
                processes = []
                try:
                    processes.append(subprocess.Popen([str(self.reference), reference_mode, '-c', str(rfile)], stdout=rlog, stderr=rlog))
                    processes.append(subprocess.Popen([str(BIN), '--config', str(pfile), *project_args], stdout=plog, stderr=plog))
                    deadline = time.monotonic() + 8
                    while True:
                        if any(p.poll() is not None for p in processes):
                            self.fail('process stopped before listener readiness')
                        try:
                            with socket.create_connection(('127.0.0.1', socks_port), .2):
                                break
                        except OSError:
                            if time.monotonic() > deadline:
                                self.fail('SOCKS listener did not become ready')
                            time.sleep(.03)
                    # UDP listeners have no TCP readiness endpoint. Retry only
                    # before application payload; never replay delivered data.
                    time.sleep(.1)
                    yield socks_port
                except BaseException as error:
                    plog.flush(); rlog.flush()
                    error.add_note((root / 'project.log').read_text(errors='replace')[-3500:])
                    error.add_note((root / 'reference.log').read_text(errors='replace')[-3500:])
                    raise
                finally:
                    for p in reversed(processes):
                        if p.poll() is None:
                            p.terminate()
                        try:
                            p.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            p.kill(); p.wait(timeout=3)

    def socks(self, port, command, target):
        c = socket.create_connection(('127.0.0.1', port), 5)
        c.settimeout(5)
        try:
            c.sendall(b'\x05\x01\x00')
            self.assertEqual(exact(c, 2), b'\x05\x00')
            c.sendall(bytes([5, command, 0, 1]) + socket.inet_aton(target[0]) + target[1].to_bytes(2, 'big'))
            h = exact(c, 4)
            self.assertEqual(h[:2], b'\x05\x00')
            if h[3] == 1:
                tail = exact(c, 6); address = socket.inet_ntoa(tail[:4]), int.from_bytes(tail[4:], 'big')
            elif h[3] == 4:
                tail = exact(c, 18); address = socket.inet_ntop(socket.AF_INET6, tail[:16]), int.from_bytes(tail[16:], 'big')
            else:
                n = exact(c, 1)[0]; tail = exact(c, n + 2); address = tail[:n].decode(), int.from_bytes(tail[n:], 'big')
            return c, address
        except BaseException:
            c.close(); raise

    def test_official_client_and_server_tcp_udp(self):
        for server in [False, True]:
            for mode in ['none', 'salamander', 'gecko']:
                with self.subTest(project_is_server=server, obfs=mode):
                    tcp, udp = socket.socket(), socket.socket(type=socket.SOCK_DGRAM)
                    tcp.bind(('127.0.0.1', 0)); tcp.listen(); tcp.settimeout(.2)
                    udp.bind(('127.0.0.1', 0)); udp.settimeout(.2)
                    stop = threading.Event()
                    def echo_tcp():
                        while not stop.is_set():
                            try:
                                c, _ = tcp.accept()
                            except (TimeoutError, OSError):
                                continue
                            with c:
                                c.settimeout(5)
                                while data := c.recv(65535):
                                    c.sendall(data)
                    def echo_udp():
                        while not stop.is_set():
                            try:
                                data, a = udp.recvfrom(65535); udp.sendto(data, a)
                            except (TimeoutError, OSError):
                                continue
                    workers = [threading.Thread(target=echo_tcp), threading.Thread(target=echo_udp)]
                    for w in workers: w.start()
                    try:
                        with self.pair(server, mode) as socks:
                            for cycle in range(4):
                                c, _ = self.socks(socks, 1, tcp.getsockname())
                                with c:
                                    payload = b'official Hysteria bidirectional TCP\x00\xff' * 128
                                    c.sendall(payload); self.assertEqual(exact(c, len(payload)), payload)
                            control, relay = self.socks(socks, 3, ('0.0.0.0', 0))
                            with control, socket.socket(type=socket.SOCK_DGRAM) as client:
                                client.bind(('127.0.0.1', 0)); client.settimeout(5)
                                destination = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + udp.getsockname()[1].to_bytes(2, 'big')
                                for size in [32, 1400, 3800]:
                                    body = b'z' * size
                                    client.sendto(destination + body, relay)
                                    response, _ = client.recvfrom(65535)
                                    self.assertEqual(response[10:], body)
                    finally:
                        stop.set(); tcp.close(); udp.close()
                        for w in workers:
                            w.join(timeout=6); self.assertFalse(w.is_alive())
