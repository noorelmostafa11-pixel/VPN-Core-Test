"""Shadowsocks TCP/native UDP against official sing-box, using synthetic keys."""
import base64
import contextlib
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import quote

from test_core import BIN, exact, free_port
import test_hysteria_reference as hyref


def secret(method, chain=1):
    if not method.startswith('2022-'):
        return 'synthetic-ss-server-password'
    size = 16 if '128' in method else 32
    return ':'.join(base64.b64encode(bytes([i + 31]) * size).decode() for i in range(chain))


class SSServerReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = pathlib.Path(os.environ.get('VPN_CORE_REFERENCE_SINGBOX', ''))
        if not cls.reference.is_file():
            raise unittest.SkipTest('set VPN_CORE_REFERENCE_SINGBOX to the official sing-box executable')
        cls.version = subprocess.check_output([str(cls.reference), 'version'], text=True).splitlines()[0]
        if '1.14.3' not in cls.version:
            raise unittest.SkipTest('this fixture records sing-box 1.14.3 acceptance')

    def socks(self, *args):
        return hyref.HysteriaReferenceTests.socks(self, *args)

    @contextlib.contextmanager
    def pair(self, project_server, method, chain=1):
        server, socks = free_port(), free_port()
        key = secret(method, chain)
        if project_server:
            project = {'outbounds': [{'tag': 'direct', 'uri': 'direct://'}], 'final': 'direct',
                       'inbounds': [{'protocol': 'ss', 'listen': f'127.0.0.1:{server}', 'cipher': method, 'password': key}]}
            reference = {'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': socks}],
                         'outbounds': [{'type': 'shadowsocks', 'server': '127.0.0.1', 'server_port': server,
                                        'method': method, 'password': key}]}
        else:
            uri = f'ss://{method}:{quote(key, safe="")}@127.0.0.1:{server}'
            project = {'listen_port': socks, 'outbounds': [{'tag': 'ss', 'uri': uri}], 'final': 'ss'}
            inbound = {'type': 'shadowsocks', 'listen': '127.0.0.1', 'listen_port': server, 'method': method,
                       'password': key}
            reference = {'inbounds': [inbound], 'outbounds': [{'type': 'direct'}]}
        with tempfile.TemporaryDirectory(prefix='vpn-ss-server-reference-') as temp:
            root = pathlib.Path(temp)
            pp, rp = root / 'project.json', root / 'reference.json'
            pp.write_text(json.dumps(project), encoding='utf-8')
            rp.write_text(json.dumps(reference), encoding='utf-8')
            processes = []
            with (root / 'project.log').open('w') as plog, (root / 'reference.log').open('w') as rlog:
                try:
                    for args, log in [([str(BIN), '--config', str(pp)] + (['--no-socks'] if project_server else []), plog),
                                      ([str(self.reference), 'run', '-c', str(rp)], rlog)]:
                        processes.append(subprocess.Popen(args, stdout=log, stderr=log))
                    deadline = time.monotonic() + 8
                    while True:
                        if any(p.poll() is not None for p in processes):
                            self.fail('project/reference stopped before readiness')
                        try:
                            for port in [server, socks]:
                                with socket.create_connection(('127.0.0.1', port), .2):
                                    pass
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                self.fail('listener readiness timeout')
                            time.sleep(.03)
                    yield socks
                except BaseException as error:
                    plog.flush(); rlog.flush()
                    error.add_note((root / 'project.log').read_text(errors='replace')[-4000:])
                    error.add_note((root / 'reference.log').read_text(errors='replace')[-4000:])
                    raise
                finally:
                    for p in reversed(processes):
                        if p.poll() is None:
                            p.terminate()
                        try:
                            p.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            p.kill(); p.wait(timeout=3)

    def payload(self, project_server, method, chain=1):
        tcp, udp = socket.socket(), socket.socket(type=socket.SOCK_DGRAM)
        tcp.bind(('127.0.0.1', 0)); tcp.listen(); tcp.settimeout(.2)
        udp.bind(('127.0.0.1', 0)); udp.settimeout(.2)
        stop, workers = threading.Event(), []
        def handle(c):
            try:
                with c:
                    c.settimeout(5)
                    while data := c.recv(65535): c.sendall(data)
            except OSError:
                pass
        def accept():
            while not stop.is_set():
                try: c, _ = tcp.accept()
                except OSError: continue
                worker = threading.Thread(target=handle, args=(c,)); workers.append(worker); worker.start()
        def echo_udp():
            while not stop.is_set():
                try: data, addr = udp.recvfrom(65535); udp.sendto(data, addr)
                except OSError: continue
        listeners = [threading.Thread(target=accept), threading.Thread(target=echo_udp)]
        for worker in listeners: worker.start()
        try:
            with self.pair(project_server, method, chain) as socks:
                for cycle in range(16):
                    c, _ = self.socks(socks, 1, tcp.getsockname())
                    with c:
                        c.settimeout(5)
                        body = bytes([cycle + 31]) * 200001
                        c.sendall(body); self.assertEqual(exact(c, len(body)), body)
                for cycle in range(8):
                    control, relay = self.socks(socks, 3, ('0.0.0.0', 0))
                    with control, socket.socket(type=socket.SOCK_DGRAM) as client:
                        client.bind(('127.0.0.1', 0)); client.settimeout(5)
                        header = b'\0\0\0\1' + socket.inet_aton('127.0.0.1') + udp.getsockname()[1].to_bytes(2, 'big')
                        for size in [32, 1400, 3800]:
                            body = bytes([cycle + 11]) * size
                            client.sendto(header + body, relay)
                            response, _ = client.recvfrom(65535)
                            self.assertEqual(response[10:], body)
        finally:
            stop.set(); tcp.close(); udp.close()
            for worker in listeners: worker.join(timeout=6); self.assertFalse(worker.is_alive())
            for worker in workers: worker.join(timeout=6); self.assertFalse(worker.is_alive())

    def test_singbox_native_udp_and_tcp_both_directions(self):
        for project_server in [False, True]:
            for method in ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
                           '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305']:
                with self.subTest(project_server=project_server, method=method):
                    self.payload(project_server, method)

    def test_singbox_client_identity_chains(self):
        for method in ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm']:
            for chain in [2, 3]:
                with self.subTest(method=method, chain=chain):
                    self.payload(True, method, chain)
