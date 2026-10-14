"""Official Hysteria 1.3.5 processes, certificate-verified loopback payloads."""
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
import test_hysteria_reference as hyref


class Hysteria1ReferenceTests(hyref.HysteriaReferenceTests):
    @classmethod
    def setUpClass(cls):
        cls.reference = pathlib.Path(os.environ.get('VPN_CORE_REFERENCE_HYSTERIA1', ''))
        if not cls.reference.is_file():
            raise unittest.SkipTest('set VPN_CORE_REFERENCE_HYSTERIA1 to official Hysteria 1.3.5')
        cls.version = subprocess.check_output([str(cls.reference), '--version'], text=True)
        if 'v1.3.5' not in cls.version or '57c5164854d6cfe00bead730cce731da2babe406' not in cls.version:
            raise unittest.SkipTest('this fixture pins official Hysteria 1.3.5 / 57c5164')
        cls.temp = tempfile.TemporaryDirectory(prefix='vpn-hysteria1-reference-')
        cls.root = pathlib.Path(cls.temp.name)
        openssl = shutil.which('openssl')
        if not openssl and os.name == 'nt':
            candidate = pathlib.Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/usr/bin/openssl.exe'
            if candidate.is_file():
                openssl = str(candidate)
        if not openssl:
            cls.temp.cleanup()
            raise unittest.SkipTest('OpenSSL is needed for the synthetic certificate')
        cls.cert, cls.key = cls.root / 'cert.pem', cls.root / 'key.pem'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-keyout', str(cls.key), '-out', str(cls.cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cls.cert.read_text())).hexdigest()

    @contextlib.contextmanager
    def pair(self, project_is_server, mode):
        server_port, socks_port = free_port(), free_port()
        options = {'upmbps': '100', 'downmbps': '100'}
        shared = {'up_mbps': 100, 'down_mbps': 100, 'alpn': 'hysteria', 'disable_mtu_discovery': True}
        if mode == 'xplus':
            options.update(obfs='xplus', obfsparam='synthetic-obfs-secret')
            shared['obfs'] = 'synthetic-obfs-secret'
        if project_is_server:
            spec = {'protocol': 'hysteria', 'listen': f'127.0.0.1:{server_port}',
                    'password': 'synthetic-auth', 'cert_file': str(self.cert),
                    'key_file': str(self.key), 'options': options}
            project = {'outbounds': [{'tag': 'direct', 'uri': 'direct://'}], 'final': 'direct', 'inbounds': [spec]}
            reference = {'server': f'127.0.0.1:{server_port}', 'auth_str': 'synthetic-auth',
                         'server_name': 'localhost', 'ca': str(self.cert),
                         'socks5': {'listen': f'127.0.0.1:{socks_port}'}, **shared}
            project_args, reference_mode = ['--no-socks'], 'client'
        else:
            query = '&'.join(f'{k}={v}' for k, v in options.items())
            uri = f'hysteria://127.0.0.1:{server_port}?auth=synthetic-auth&peer=localhost&pinsha256={self.pin}&{query}'
            project = {'listen_port': socks_port, 'outbounds': [{'tag': 'hy', 'uri': uri}], 'final': 'hy'}
            reference = {'listen': f'127.0.0.1:{server_port}', 'cert': str(self.cert), 'key': str(self.key),
                         'auth': {'mode': 'passwords', 'config': ['synthetic-auth']}, **shared}
            project_args, reference_mode = [], 'server'
        with tempfile.TemporaryDirectory(dir=self.root) as temp:
            root = pathlib.Path(temp)
            pfile, rfile = root / 'project.json', root / 'reference.json'
            pfile.write_text(json.dumps(project), encoding='utf-8')
            rfile.write_text(json.dumps(reference), encoding='utf-8')
            with (root / 'project.log').open('w') as plog, (root / 'reference.log').open('w') as rlog:
                processes = []
                try:
                    # The official v1 client connects eagerly: start the server first.
                    commands = [[str(BIN), '--config', str(pfile), *project_args],
                                [str(self.reference), '-c', str(rfile), reference_mode]]
                    if not project_is_server:
                        commands.reverse()
                    processes.append(subprocess.Popen(commands[0], stdout=plog if project_is_server else rlog,
                                                      stderr=plog if project_is_server else rlog))
                    time.sleep(.2)
                    processes.append(subprocess.Popen(commands[1], stdout=rlog if project_is_server else plog,
                                                      stderr=rlog if project_is_server else plog))
                    deadline = time.monotonic() + 8
                    while True:
                        if any(p.poll() is not None for p in processes):
                            self.fail('process stopped before listener readiness')
                        try:
                            with socket.create_connection(('127.0.0.1', socks_port), .2):
                                break
                        except OSError:
                            if time.monotonic() > deadline:
                                self.fail('SOCKS listener not ready')
                            time.sleep(.03)
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

    def test_official_client_and_server_tcp_udp(self):
        for server in [False, True]:
            for mode in ['none', 'xplus']:
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
                            for cycle in range(16):
                                c, _ = self.socks(socks, 1, tcp.getsockname())
                                with c:
                                    payload = b'official Hysteria 1 bidirectional TCP\x00\xff' * 128
                                    c.sendall(payload); self.assertEqual(exact(c, len(payload)), payload)
                            for cycle in range(8):
                                control, relay = self.socks(socks, 3, ('0.0.0.0', 0))
                                with control, socket.socket(type=socket.SOCK_DGRAM) as client:
                                    client.bind(('127.0.0.1', 0)); client.settimeout(5)
                                    destination = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + udp.getsockname()[1].to_bytes(2, 'big')
                                    # Official 1.3.5 server reads UDP into a 4096-byte buffer.
                                    for size in [32, 1400, 3800]:
                                        body = b'z' * size
                                        client.sendto(destination + body, relay)
                                        response, _ = client.recvfrom(65535)
                                        self.assertEqual(response[10:], body)
                    finally:
                        stop.set(); tcp.close(); udp.close()
                        for w in workers:
                            w.join(timeout=6); self.assertFalse(w.is_alive())
