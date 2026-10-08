"""Independent protocol oracle and local TLS integration tests; no public nodes.

Python's hashlib verifies SHA224 independently. The mock server parses the
published Trojan wire format without using the C++ implementation. An optional
external Trojan 1.16.0 server verifies interoperability with another project.
"""
import concurrent.futures
import contextlib
import hashlib
import json
import os
import pathlib
import random
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import quote

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = pathlib.Path(os.environ.get('VPN_CORE_TEST_BINARY', str(ROOT / 'bin/vpn-core-test')))
PASSWORD = 'synthetic-local-test+password;not-a-production-credential'

def command(*args):
    return [str(BIN)] + [str(a) for a in args]

def exact(sock, n):
    out = b''
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part:
            raise EOFError('short message')
        out += part
    return out

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class MockTrojan:
    def __init__(self, cert, key, greeting=b''):
        self.greeting = greeting
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.maximum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(64)
        self.listener.settimeout(.2)
        self.stop = threading.Event()
        self.received = []
        self.errors = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                sock, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.handle, args=(sock,), daemon=True).start()

    def handle(self, raw):
        try:
            raw.settimeout(6)
            with self.context.wrap_socket(raw, server_side=True) as tls:
                auth = exact(tls, 56)
                if exact(tls, 2) != b'\r\n':
                    raise ValueError('bad authentication delimiter')
                if auth != hashlib.sha224(PASSWORD.encode()).hexdigest().encode():
                    tls.unwrap().close()
                    return
                if exact(tls, 1) != b'\x01':
                    raise ValueError('bad Trojan command')
                atyp = exact(tls, 1)
                if atyp == b'\x01':
                    address = exact(tls, 4)
                elif atyp == b'\x04':
                    address = exact(tls, 16)
                elif atyp == b'\x03':
                    size = exact(tls, 1)
                    address = size + exact(tls, size[0])
                else:
                    raise ValueError('bad address type')
                port = exact(tls, 2)
                if exact(tls, 2) != b'\r\n':
                    raise ValueError('bad request delimiter')
                self.received.append(atyp + address + port)
                if self.greeting:
                    tls.sendall(self.greeting)
                while True:
                    data = tls.recv(4096)
                    if not data:
                        tls.unwrap().close()
                        return
                    tls.sendall(data)
        except (ssl.SSLError, EOFError, TimeoutError, ConnectionError, OSError):
            # Expected for malformed greeting/verification/disconnect tests.
            raw.close()
        except Exception as e:
            self.errors.append(repr(e))
            raw.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(2)

class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='vpn-core-tests-')
        cls.directory = pathlib.Path(cls.tmp.name)
        def run(*args):
            subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.ca = cls.directory / 'ca.pem'
        ca_key = cls.directory / 'ca.key'
        cls.cert = cls.directory / 'server.pem'
        cls.key = cls.directory / 'server.key'
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(ca_key), '-out', str(cls.ca), '-days', '2', '-subj', '/CN=VPNCoreEphemeralTestCA', '-addext', 'basicConstraints=critical,CA:TRUE')
        csr = cls.directory / 'server.csr'
        run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(cls.key), '-out', str(csr), '-subj', '/CN=localhost')
        ext = cls.directory / 'extensions.txt'
        ext.write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        run('openssl', 'x509', '-req', '-in', str(csr), '-CA', str(cls.ca), '-CAkey', str(ca_key), '-CAcreateserial', '-out', str(cls.cert), '-days', '2', '-extfile', str(ext))
        cls.mock = MockTrojan(cls.cert, cls.key)

    @classmethod
    def tearDownClass(cls):
        cls.mock.close()
        cls.tmp.cleanup()

    def uri(self, *, password=PASSWORD, name='localhost', port=None, options=''):
        return 'trojan://' + quote(password, safe='') + '@127.0.0.1:' + str(port or self.mock.port) + '?type=tcp&security=tls&sni=' + name + options

    @contextlib.contextmanager
    def core(self, *, uri=None, timeout=1000, ca=True):
        port = free_port()
        cfg = self.directory / ('node-' + str(port) + '.ini')
        text = f'node_uri={uri or self.uri()}\nlisten_port={port}\nconnect_timeout_ms=2000\nidle_timeout_ms={timeout}\n'
        if ca:
            text += 'test_ca_file=' + str(self.ca) + '\n'
        cfg.write_text(text, encoding='utf8')
        logfile = self.directory / ('log-' + str(port) + '.txt')
        with logfile.open('w') as log:
            process = subprocess.Popen(command('--config', str(cfg)), stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        self.fail('core startup failed: ' + logfile.read_text())
                    try:
                        with socket.create_connection(('127.0.0.1', port), .1):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            self.fail('core listener timeout: ' + logfile.read_text())
                        time.sleep(.03)
                yield port, logfile
            finally:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                cfg.unlink(missing_ok=True)
        logs = logfile.read_text()
        self.assertNotIn(PASSWORD, logs)
        self.assertNotIn(quote(PASSWORD, safe=''), logs)
        self.assertNotIn(hashlib.sha224(PASSWORD.encode()).hexdigest(), logs)

    def socks(self, port, address=b'\x03\x0cexample.test\x01\xbb', *, expected=0):
        s = socket.create_connection(('127.0.0.1', port), 5)
        s.settimeout(6)
        # Fragment the greeting and the request deliberately.
        for b in b'\x05\x01\x00':
            s.sendall(bytes([b]))
        self.assertEqual(exact(s, 2), b'\x05\x00')
        for b in b'\x05\x01\x00' + address:
            s.sendall(bytes([b]))
        self.assertEqual(exact(s, 10)[1], expected)
        return s

    def test_01_standard_vectors(self):
        result = subprocess.run(command('--self-test'), capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_02_sha224_differential(self):
        rng = random.Random(73442)
        values = [b'', b'abc', b'a' * 1000000] + [rng.randbytes(n) for n in range(0, 260)] + [rng.randbytes(rng.randrange(1, 10000)) for _ in range(100)]
        result = subprocess.run([os.environ.get('VPN_CORE_PROTOCOL_PROBE',str(ROOT / 'bin/protocol-probe'))], input='\n'.join(v.hex() for v in values) + '\n', capture_output=True, text=True, check=True, timeout=20)
        self.assertEqual(result.stdout.splitlines(), [hashlib.sha224(v).hexdigest() for v in values])

    def test_03_config_rejections(self):
        bad = [self.uri(options='&fp=invalid-unregistered-profile'), self.uri(options='&flow=xtls-rprx-vision'), 'trojan://secret@x:0', 'vless://@x:443', 'trojan://secret@x:443?security=reality', 'trojan://secret@x:443?type=xhttp&mode=invalid-unregistered-mode', 'trojan://secret@x:443?pinned-peer-cert-sha256=synthetic-test-pin']
        path = self.directory / 'bad.ini'
        for uri in bad:
            with self.subTest(uri_kind=uri.split('://')[0]):
                path.write_text('node_uri=' + uri + '\n')
                result = subprocess.run(command('--config', str(path), '--check-config'), capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(PASSWORD, result.stdout + result.stderr)
                self.assertNotIn('secret', result.stdout + result.stderr)

    def test_04_destination_types(self):
        addresses = [b'\x01\x7f\x00\x00\x01\x01\xbb', b'\x04' + socket.inet_pton(socket.AF_INET6, '::1') + b'\x01\xbb', b'\x03\x0cexample.test\x01\xbb']
        with self.core() as (port, _):
            for address in addresses:
                with self.socks(port, address) as s:
                    s.sendall(b'hello\x00Trojan')
                    self.assertEqual(exact(s, 12), b'hello\x00Trojan')
            for address in addresses:
                self.assertIn(address, self.mock.received)
        self.assertEqual(self.mock.errors, [])

    def test_05_large_bidirectional_stream(self):
        payload = random.Random(99).randbytes(3 * 1024 * 1024)
        with self.core(timeout=15000) as (port, _):
            with self.socks(port) as s:
                errors = []
                def writer():
                    try:
                        s.sendall(payload)
                    except Exception as e:
                        errors.append(e)
                thread = threading.Thread(target=writer)
                thread.start()
                received = exact(s, len(payload))
                thread.join(10)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(hashlib.sha256(received).digest(), hashlib.sha256(payload).digest())

    def test_06_concurrent_streams(self):
        with self.core(timeout=10000) as (port, _):
            def exchange(i):
                payload = bytes([i]) * 32768
                with self.socks(port) as s:
                    s.sendall(payload)
                    return exact(s, len(payload)) == payload
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                self.assertTrue(all(pool.map(exchange, range(8))))

    def test_07_wrong_certificate_name(self):
        with self.core(uri=self.uri(name='wrong.invalid')) as (port, _):
            self.socks(port, expected=1).close()

    def test_08_untrusted_certificate(self):
        with self.core(ca=False) as (port, _):
            self.socks(port, expected=1).close()

    def test_09_wrong_password_no_data(self):
        with self.core(uri=self.uri(password='wrong-local-test-password')) as (port, _):
            with self.socks(port) as s:
                s.sendall(b'never-direct')
                try:
                    self.assertEqual(s.recv(1024), b'')
                except ConnectionResetError:
                    pass

    def test_10_unsupported_command(self):
        with self.core() as (port, _):
            with socket.create_connection(('127.0.0.1', port), 5) as s:
                s.settimeout(3)
                s.sendall(b'\x05\x01\x00')
                self.assertEqual(exact(s, 2), b'\x05\x00')
                s.sendall(b'\x05\x02\x00\x01')
                self.assertEqual(exact(s, 10)[1], 7)

    def test_11_empty_domain(self):
        with self.core() as (port, _):
            with socket.create_connection(('127.0.0.1', port), 5) as s:
                s.settimeout(3)
                s.sendall(b'\x05\x01\x00')
                exact(s, 2)
                s.sendall(b'\x05\x01\x00\x03\x00')
                self.assertEqual(exact(s, 10)[1], 8)

    def test_12_idle_timeout(self):
        with self.core(timeout=1000) as (port, _):
            with self.socks(port) as s:
                s.sendall(b'ping')
                self.assertEqual(exact(s, 4), b'ping')
                time.sleep(1.5)
                self.assertEqual(s.recv(1), b'')

    def test_13_half_close(self):
        with self.core() as (port, _):
            with self.socks(port) as s:
                s.sendall(b'last-message')
                s.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(s, 12), b'last-message')
                self.assertEqual(s.recv(1), b'')

    @unittest.skipUnless(os.environ.get('VPN_CORE_REFERENCE_SERVER'), 'external reference server path not supplied')
    def test_14_external_trojan_https(self):
        reference_port = free_port()
        origin = socket.socket()
        origin.bind(('127.0.0.1', 0))
        origin.listen(1)
        origin_port = origin.getsockname()[1]
        expected_body = b'Independent core -> reference Trojan -> HTTPS origin\n'
        error = []
        def serve_origin():
            try:
                raw, _ = origin.accept()
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(self.cert, self.key)
                with ctx.wrap_socket(raw, server_side=True) as tls:
                    request = b''
                    while b'\r\n\r\n' not in request:
                        request += tls.recv(4096)
                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(expected_body)).encode() + b'\r\nConnection: close\r\n\r\n' + expected_body)
                    try:
                        tls.unwrap().close()
                    except (ssl.SSLError, OSError):
                        pass
            except Exception as e:
                error.append(repr(e))
        thread = threading.Thread(target=serve_origin, daemon=True)
        thread.start()
        ref_cfg = self.directory / 'reference.json'
        ref_cfg.write_text(json.dumps({'run_type':'server','local_addr':'127.0.0.1','local_port':reference_port,'remote_addr':'127.0.0.1','remote_port':1,'password':[PASSWORD],'log_level':2,'ssl':{'cert':str(self.cert),'key':str(self.key),'alpn':['http/1.1']}}))
        proc = subprocess.Popen([os.environ['VPN_CORE_REFERENCE_SERVER'], '-c', str(ref_cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(.3)
            self.assertIsNone(proc.poll())
            with self.core(uri=self.uri(port=reference_port), timeout=10000) as (port, _):
                env = os.environ.copy()
                env.pop('NO_PROXY', None)
                env.pop('no_proxy', None)
                result = subprocess.run(['curl','--proxy',f'socks5h://127.0.0.1:{port}','--noproxy','not-used.invalid','--cacert',str(self.ca),'--max-time','15','--fail','--silent','--show-error',f'https://127.0.0.1:{origin_port}/'], env=env, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                self.assertEqual(result.stdout, expected_body)
        finally:
            proc.terminate()
            proc.wait(5)
            origin.close()
        thread.join(3)
        self.assertEqual(error, [])

    def test_15_server_first_stream(self):
        banner = b'SSH-2.0-synthetic-test\r\n'
        peer = MockTrojan(self.cert, self.key, greeting=banner)
        try:
            with self.core(uri=self.uri(port=peer.port)) as (port, _):
                with self.socks(port) as s:
                    self.assertEqual(exact(s, len(banner)), banner)
                    s.sendall(b'after-banner')
                    self.assertEqual(exact(s, 12), b'after-banner')
            self.assertEqual(peer.errors, [])
        finally:
            peer.close()

    @unittest.skipUnless(os.environ.get('VPN_CORE_REFERENCE_SERVER'), 'external reference server path not supplied')
    def test_16_reference_server_first(self):
        banner = b'220 synthetic server ready\r\n'
        origin = socket.socket()
        origin.bind(('127.0.0.1', 0))
        origin.listen(1)
        origin.settimeout(5)
        origin_port = origin.getsockname()[1]
        errors = []
        def serve():
            try:
                with origin.accept()[0] as s:
                    s.settimeout(5)
                    s.sendall(banner)
                    s.sendall(exact(s, 4))
            except Exception as e:
                errors.append(repr(e))
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        reference_port = free_port()
        ref_cfg = self.directory / 'reference-banner.json'
        ref_cfg.write_text(json.dumps({'run_type':'server','local_addr':'127.0.0.1','local_port':reference_port,'remote_addr':'127.0.0.1','remote_port':1,'password':[PASSWORD],'log_level':2,'ssl':{'cert':str(self.cert),'key':str(self.key)}}))
        proc = subprocess.Popen([os.environ['VPN_CORE_REFERENCE_SERVER'], '-c', str(ref_cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(.3)
            self.assertIsNone(proc.poll())
            with self.core(uri=self.uri(port=reference_port)) as (port, _):
                address = b'\x01\x7f\x00\x00\x01' + struct.pack('!H', origin_port)
                with self.socks(port, address) as s:
                    self.assertEqual(exact(s, len(banner)), banner)
                    s.sendall(b'ping')
                    self.assertEqual(exact(s, 4), b'ping')
        finally:
            proc.terminate()
            proc.wait(5)
            origin.close()
        thread.join(6)
        self.assertEqual(errors, [])

    def test_17_no_supported_authentication(self):
        with self.core() as (port, _):
            with socket.create_connection(('127.0.0.1', port), 5) as s:
                s.settimeout(3)
                s.sendall(b'\x05\x01\x02')
                self.assertEqual(exact(s, 2), b'\x05\xff')
                self.assertEqual(s.recv(1), b'')

    def test_18_config_in_unicode_directory(self):
        directory = self.directory / 'إعدادات الاختبار'
        directory.mkdir(exist_ok=True)
        cfg = directory / 'node.ini'
        cfg.write_text('node_uri=' + self.uri() + '\n', encoding='utf8')
        result = subprocess.run(command('--config', str(cfg), '--check-config'), capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_19_tls12_cbc_rejected(self):
        peer=MockTrojan(self.cert,self.key)
        peer.context.set_ciphers('ECDHE-RSA-AES256-SHA')
        try:
            for fp in ('','chrome'):
                with self.subTest(fp=fp),self.core(uri=self.uri(port=peer.port,options='&fp='+fp)) as (port,log):
                    with self.socks(port,expected=1):pass
        finally:peer.close()

if __name__ == '__main__':
    unittest.main(verbosity=2)
