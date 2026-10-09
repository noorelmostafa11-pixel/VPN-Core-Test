"""Independent Python peers and third-party HTTP/2 oracle; never use public nodes.

cryptography and hyper-h2 are test-only dependencies, absent from the core.
"""
import base64
import concurrent.futures
import contextlib
import hashlib
import hmac
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
import uuid
import zlib
from urllib.parse import quote
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded
from h2.settings import SettingCodes
from hpack import Encoder
import test_core as original
from test_core import exact, ROOT, BIN

ID = uuid.UUID('12345678-1234-4567-9234-567812345678')
SECRET = 'synthetic-only-password'
HELLO = b'SERVER-FIRST: independent peer\n'

def khash(key, message, digest):
    if len(key) > 64:
        key = digest(key)
    key = key.ljust(64, b'\0')
    return digest(bytes(x ^ 0x5c for x in key) + digest(bytes(x ^ 0x36 for x in key) + message))

def kdf(key, *path):
    digest = lambda data: hashlib.sha256(data).digest()
    for item in (b'VMess AEAD KDF',) + path:
        parent = digest
        digest = lambda data, parent=parent, item=item: khash(item, data, parent)
    return digest(key)

def fnv(data):
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return value

def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    return bytes(out) + bytes([value])

class Wrapped:
    def __init__(self, sock, transport, bad=False, path='/test/Tun'):
        self.sock, self.transport, self.bad = sock, transport, bad
        self.buffer = bytearray()
        self.grpc_buffer = bytearray()
        self.ended = False
        if transport in ('websocket', 'httpupgrade'):
            request = bytearray()
            while not request.endswith(b'\r\n\r\n'):
                request += exact(sock, 1)
                if len(request) > 65536:
                    raise ValueError('large HTTP request')
            lines = request.decode().split('\r\n')
            if lines[0] != 'GET /test HTTP/1.1':
                raise ValueError('wrong upgrade path')
            headers = dict(line.lower().split(': ', 1) for line in lines[1:] if ': ' in line)
            response = b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
            if transport == 'websocket':
                # Header names insensitive, key value case-sensitive.
                key = next(line.split(': ', 1)[1] for line in lines if line.startswith('Sec-WebSocket-Key:'))
                accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
                response += b'Sec-WebSocket-Accept: ' + (b'wrong' if bad else accept) + b'\r\n'
            for byte in response + b'\r\n':
                sock.sendall(bytes([byte]))
        elif transport == 'grpc':
            self.h2 = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
            self.h2.initiate_connection()
            self.h2.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 1031})
            self.sock.sendall(self.h2.data_to_send())
            self.path = path
            while not hasattr(self, 'stream'):
                self.pump()

    def pump(self):
        wire = self.sock.recv(16384)
        if not wire:
            self.ended = True
            return
        for event in self.h2.receive_data(wire):
            if isinstance(event, RequestReceived):
                headers = dict(event.headers)
                if headers[':path'] != self.path or headers['content-type'] != 'application/grpc':
                    raise ValueError('wrong gRPC request')
                self.stream = event.stream_id
                self.h2.send_headers(self.stream, [(':status', '200'), ('content-type', 'application/grpc'), ('grpc-encoding', 'identity')])
            elif isinstance(event, DataReceived):
                self.grpc_buffer += event.data
                self.h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                while len(self.grpc_buffer) >= 5:
                    n = int.from_bytes(self.grpc_buffer[1:5], 'big')
                    if len(self.grpc_buffer) < n + 5:
                        break
                    if self.grpc_buffer[0]:
                        raise ValueError('gRPC compressed request')
                    body = self.grpc_buffer[5:n+5]
                    del self.grpc_buffer[:n+5]
                    if body[0] != 10:
                        raise ValueError('Hunk field')
                    pos, size, shift = 1, 0, 0
                    while True:
                        byte = body[pos]
                        pos += 1
                        size |= (byte & 127) << shift
                        if not byte & 128:
                            break
                        shift += 7
                    if len(body) - pos != size:
                        raise ValueError('Hunk length')
                    self.buffer += body[pos:]
            elif isinstance(event, StreamEnded):
                self.ended = True
                self.h2.send_headers(self.stream, [('grpc-status', '0')], end_stream=True)
        self.sock.sendall(self.h2.data_to_send())

    def recv(self, n):
        if self.transport in ('raw', 'httpupgrade'):
            return self.sock.recv(n)
        while not self.buffer and not self.ended:
            if self.transport == 'grpc':
                self.pump()
            else:
                head = exact(self.sock, 2)
                opcode, length = head[0] & 15, head[1] & 127
                if not head[1] & 128:
                    raise ValueError('unmasked client WebSocket')
                if length == 126:
                    length = int.from_bytes(exact(self.sock, 2), 'big')
                elif length == 127:
                    length = int.from_bytes(exact(self.sock, 8), 'big')
                mask = exact(self.sock, 4)
                data = exact(self.sock, length)
                data = bytes(x ^ mask[i % 4] for i, x in enumerate(data))
                if opcode == 8:
                    self.sock.sendall(b'\x88\x00')
                    self.ended = True
                elif opcode == 2:
                    self.buffer += data
                elif opcode != 10:
                    raise ValueError('unexpected client opcode')
        out = bytes(self.buffer[:n])
        del self.buffer[:n]
        return out

    def sendall(self, data):
        if self.transport in ('raw', 'httpupgrade'):
            self.sock.sendall(data)
        elif self.transport == 'websocket':
            # Fragment every message, interleaving ping controls.
            cut = len(data) // 2
            for opcode, part in ((2, data[:cut]), (0x89, b'ping'), (0x80, data[cut:])):
                length = len(part)
                header = bytes([opcode, length]) if length < 126 else bytes([opcode, 126]) + struct.pack('!H', length)
                self.sock.sendall(header + part)
        else:
            body = b'\x0a' + varint(len(data)) + data
            if self.path.endswith('/TunMulti'):
                cut=len(data)//2
                body=b'\x0a'+varint(cut)+data[:cut]+b'\x0a'+varint(len(data)-cut)+data[cut:]
            message = b'\0' + struct.pack('!I', len(body)) + body
            pos = 0
            while pos < len(message):
                window = self.h2.local_flow_control_window(self.stream)
                if window <= 0:
                    self.pump()
                    continue
                n = min(window, self.h2.max_outbound_frame_size, len(message) - pos)
                self.h2.send_data(self.stream, message[pos:pos+n])
                pos += n
                self.sock.sendall(self.h2.data_to_send())

class Peer:
    def __init__(self, protocol, cipher='', transport='raw', tls_context=None, corrupt=False, path='/test/Tun'):
        self.protocol, self.cipher, self.transport = protocol, cipher, transport
        self.tls_context, self.corrupt, self.path = tls_context, corrupt, path
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(64)
        self.listener.settimeout(.2)
        self.stop = threading.Event()
        self.errors = []
        self.accepted = 0
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
        sock = raw
        try:
            raw.settimeout(10)
            sock = self.tls_context.wrap_socket(raw, server_side=True) if self.tls_context else raw
            wire = Wrapped(sock, self.transport, self.corrupt and self.transport == 'websocket', self.path)
            if self.corrupt and self.transport == 'websocket':
                return
            if self.protocol == 'trojan':
                if exact(wire, 56) != hashlib.sha224(SECRET.encode()).hexdigest().encode() or exact(wire, 3) != b'\r\n\1':
                    raise ValueError('Trojan authentication')
                atyp = exact(wire,1)
                if atyp == b'\3': exact(wire,exact(wire,1)[0])
                elif atyp in (b'\1',b'\4'): exact(wire,4 if atyp==b'\1' else 16)
                else: raise ValueError('Trojan address')
                exact(wire,2)
                if exact(wire,2)!=b'\r\n': raise ValueError('Trojan delimiter')
                if not getattr(self,'forward_target',None):wire.sendall(HELLO)
                receive=lambda: wire.recv(8192)
                send=wire.sendall
            elif self.protocol == 'vless':
                if exact(wire, 18) != b'\0' + ID.bytes + b'\0' or exact(wire, 1) != b'\1':
                    raise ValueError('VLESS authentication')
                port, atyp = exact(wire, 2), exact(wire, 1)
                if atyp == b'\2':
                    host = exact(wire, exact(wire, 1)[0])
                elif atyp in (b'\1', b'\3'):
                    host = exact(wire, 4 if atyp == b'\1' else 16)
                else:
                    raise ValueError('VLESS address')
                wire.sendall(b'\0\0' + (b'' if getattr(self,'forward_target',None) else HELLO))
                receive = lambda: wire.recv(8192)
                send = wire.sendall
            elif self.protocol == 'ss':
                size = 16 if self.cipher == 'aes-128-gcm' else 24 if self.cipher == 'aes-192-gcm' else 32
                master, prior = b'', b''
                while len(master) < size:
                    prior = hashlib.md5(prior + SECRET.encode()).digest()
                    master += prior
                master = master[:size]
                def subkey(salt):
                    prk = hmac.new(salt, master, 'sha1').digest()
                    a = hmac.new(prk, b'ss-subkey\1', 'sha1').digest()
                    b = hmac.new(prk, a + b'ss-subkey\2', 'sha1').digest()
                    return (a+b)[:size]
                constructor = ChaCha20Poly1305 if self.cipher == 'chacha20-ietf-poly1305' else AESGCM
                decoder = constructor(subkey(exact(wire, size)))
                salt = os.urandom(size)
                encoder = constructor(subkey(salt))
                counts = [0, 0]
                def receive():
                    encrypted = exact(wire, 18)
                    length = int.from_bytes(decoder.decrypt(counts[0].to_bytes(12, 'little'), encrypted, None), 'big')
                    counts[0] += 1
                    body = decoder.decrypt(counts[0].to_bytes(12, 'little'), exact(wire, length+16), None)
                    counts[0] += 1
                    return body
                def send(data):
                    out = encoder.encrypt(counts[1].to_bytes(12, 'little'), struct.pack('!H', len(data)), None)
                    counts[1] += 1
                    out += encoder.encrypt(counts[1].to_bytes(12, 'little'), data, None)
                    counts[1] += 1
                    wire.sendall(out)
                destination = receive()
                if not getattr(self,'forward_target',None) and destination != b'\3\x0cexample.test\x01\xbb':
                    raise ValueError('SS address')
                wire.sendall(salt)
                if self.corrupt:
                    wire.sendall(b'\0' * 18)
                    return
                if not getattr(self,'forward_target',None):send(HELLO)
            else:
                command_key = hashlib.md5(ID.bytes + b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()
                auth = exact(wire, 16)
                dec = Cipher(algorithms.AES(kdf(command_key, b'AES Auth ID Encryption')[:16]), modes.ECB()).decryptor()
                aid = dec.update(auth) + dec.finalize()
                if zlib.crc32(aid[:12]) != int.from_bytes(aid[12:], 'big') or abs(time.time() - int.from_bytes(aid[:8], 'big')) > 120:
                    raise ValueError('VMess auth ID')
                encrypted_len, nonce = exact(wire, 18), exact(wire, 8)
                def request(label, n):
                    return kdf(command_key, label, auth, nonce)[:n]
                length = int.from_bytes(AESGCM(request(b'VMess Header AEAD Key_Length', 16)).decrypt(request(b'VMess Header AEAD Nonce_Length', 12), encrypted_len, auth), 'big')
                header = AESGCM(request(b'VMess Header AEAD Key', 16)).decrypt(request(b'VMess Header AEAD Nonce', 12), exact(wire, length+16), auth)
                if fnv(header[:-4]) != int.from_bytes(header[-4:], 'big') or header[0] != 1 or header[34] != 1:
                    raise ValueError('VMess request header')
                expected=getattr(self,'expected_vmess_destination',b'\1\1\xbb\2\x0c')
                if header[35] != (5 if self.cipher=='none' else 4 if self.cipher=='chacha20-poly1305' else 3) or not getattr(self,'forward_target',None) and header[37:37+len(expected)] != expected:
                    raise ValueError('VMess body cipher or destination')
                request_iv, request_key, response_v = header[1:17], header[17:33], header[33]
                response_key = hashlib.sha256(request_key).digest()[:16]
                response_iv = hashlib.sha256(request_iv).digest()[:16]
                response = bytes([response_v, 0, 0, 0])
                response = AESGCM(kdf(response_key, b'AEAD Resp Header Len Key')[:16]).encrypt(kdf(response_iv, b'AEAD Resp Header Len IV')[:12], b'\0\4', None) + AESGCM(kdf(response_key, b'AEAD Resp Header Key')[:16]).encrypt(kdf(response_iv, b'AEAD Resp Header IV')[:12], response, None)
                if self.corrupt:
                    wire.sendall(response[:-1] + bytes([response[-1] ^ 1]))
                    return
                wire.sendall(response)
                counts = [0, 0]
                is_none = self.cipher == 'none'
                if self.cipher == 'chacha20-poly1305':
                    def expand(key):
                        a = hashlib.md5(key).digest()
                        return a + hashlib.md5(a).digest()
                    decoder, encoder = ChaCha20Poly1305(expand(request_key)), ChaCha20Poly1305(expand(response_key))
                else:
                    decoder, encoder = AESGCM(request_key), AESGCM(response_key)
                def receive():
                    n = int.from_bytes(exact(wire, 2), 'big')
                    data = exact(wire, n)
                    nonce = counts[0].to_bytes(2, 'big') + request_iv[2:12]
                    counts[0] += 1
                    return data if is_none else decoder.decrypt(nonce, data, None)
                def send(data):
                    nonce = counts[1].to_bytes(2, 'big') + response_iv[2:12]
                    counts[1] += 1
                    data = data if is_none else encoder.encrypt(nonce, data, None)
                    wire.sendall(struct.pack('!H', len(data)) + data)
                if not getattr(self,'forward_target',None):send(HELLO)
            self.accepted += 1
            if getattr(self,'forward_target',None):
                remote=socket.create_connection(self.forward_target,5)
                def upload():
                    try:
                        while True:
                            data=receive()
                            if not data:break
                            remote.sendall(data)
                    except (EOFError,OSError):pass
                    finally:
                        try:remote.shutdown(socket.SHUT_WR)
                        except OSError:pass
                threading.Thread(target=upload,daemon=True).start()
                try:
                    while True:
                        data=remote.recv(8192)
                        if not data:break
                        send(data)
                finally:remote.close()
            else:
                while True:
                    data = receive()
                    if not data:break
                    send(data)
        except (EOFError, OSError, ssl.SSLError):
            pass
        except Exception as e:
            self.errors.append(repr(e))
        finally:
            sock.close()
            raw.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(2)

class ExpandedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original.CoreTests.setUpClass()
        cls.directory = original.CoreTests.directory
        cls.ca = original.CoreTests.ca
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(original.CoreTests.cert, original.CoreTests.key)
        cls.context.minimum_version = ssl.TLSVersion.TLSv1_3
        cls.context.set_alpn_protocols(['h2', 'http/1.1'])

    @classmethod
    def tearDownClass(cls):
        original.CoreTests.tearDownClass()

    def uri(self, peer):
        query = f'?security={"tls" if peer.tls_context else "none"}&type={peer.transport}&path=%2Ftest&serviceName=test&sni=localhost'
        if peer.protocol == 'ss':
            credential = base64.urlsafe_b64encode((peer.cipher + ':' + SECRET).encode()).decode().rstrip('=')
        else:
            credential = quote(SECRET,safe='') if peer.protocol == 'trojan' else str(ID)
            if peer.protocol == 'vmess':
                query += '&encryption=' + peer.cipher
        return f'{peer.protocol}://{credential}@127.0.0.1:{peer.port}' + query

    @contextlib.contextmanager
    def core(self, uri):
        with tempfile.TemporaryDirectory(dir=self.directory) as temp:
            temp = pathlib.Path(temp)
            ready = temp / 'ready.json'
            cfg = temp / 'node.ini'
            ca_setting='tls_ca_file' if os.environ.get('VPN_CORE_TEST_PRODUCTION') else 'test_ca_file'
            cfg.write_text(f'node_uri={uri}\nlisten_port=0\nready_file={ready}\nconnect_timeout_ms=3000\nidle_timeout_ms=15000\n{ca_setting}={self.ca}\n')
            with (temp / 'core.log').open('w') as log:
                process = subprocess.Popen([str(BIN), '--config', str(cfg)], stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists():
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise AssertionError((temp / 'core.log').read_text())
                        time.sleep(.01)
                    data = json.loads(ready.read_text())
                    self.assertEqual(data['pid'], process.pid)
                    yield data['port'], temp / 'core.log'
                except BaseException as error:
                    time.sleep(.1)
                    error.add_note((temp / 'core.log').read_text())
                    raise
                finally:
                    process.terminate()
                    try:
                        process.wait(3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

    def socks(self, port):
        s = socket.create_connection(('127.0.0.1', port), 5)
        s.settimeout(15)
        s.sendall(b'\5\1\0')
        self.assertEqual(exact(s, 2), b'\5\0')
        s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb')
        self.assertEqual(exact(s, 10)[1], 0)
        return s

    def exchange(self, protocol, cipher='', transport='raw', tls=False, length=65536):
        peer = Peer(protocol, cipher, transport, self.context if tls else None)
        try:
            with self.core(self.uri(peer)) as (port, log):
                with self.socks(port) as s:
                    self.assertEqual(exact(s, len(HELLO)), HELLO)
                    payload = random.Random(56).randbytes(length)
                    errors = []
                    def writer():
                        try:
                            s.sendall(payload)
                        except Exception as e:
                            errors.append(repr(e))
                    writer = threading.Thread(target=writer)
                    writer.start()
                    self.assertEqual(hashlib.sha256(exact(s, len(payload))).digest(), hashlib.sha256(payload).digest())
                    writer.join(10)
                    self.assertFalse(writer.is_alive())
                    self.assertEqual(errors, [])
                if tls:
                    # OpenSSL test and production provider spell the same
                    # negotiated version TLSv1.3 and TLS1.3 respectively.
                    self.assertRegex(log.read_text(),r'TLSv?1\.3')
            self.assertEqual(peer.errors, [])
        finally:
            peer.close()

    def test_22_ss_aes192_gcm(self):
        self.exchange('ss','aes-192-gcm')
    def test_01_aead_differential(self):
        rng = random.Random(61)
        rows, expected = [], []
        for cipher in ('aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'):
            for n in [0, 1, 15, 16, 17, 63, 64, 65, 1024, 16383] * 5:
                key = rng.randbytes(16 if cipher == 'aes-128-gcm' else 32)
                nonce, data, aad = rng.randbytes(12), rng.randbytes(n), rng.randbytes(rng.randrange(80))
                rows.append(' '.join([cipher] + [x.hex() or '-' for x in (key, nonce, data, aad)]))
                oracle = ChaCha20Poly1305(key) if cipher == 'chacha20-ietf-poly1305' else AESGCM(key)
                expected.append(oracle.encrypt(nonce, data, aad).hex())
        result = subprocess.run([os.environ.get('VPN_CORE_CRYPTO_PROBE',str(ROOT/'bin/crypto-probe'))], input='\n'.join(rows)+'\n', capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.splitlines(), expected)

    def test_02_hpack_reference(self):
        fields = [(':status','200'), ('content-type','application/grpc'), ('grpc-status','0'), ('set-cookie','example=valid')]
        encoded = Encoder().encode(fields, huffman=True)
        result = subprocess.run([os.environ.get('VPN_CORE_CRYPTO_PROBE',str(ROOT/'bin/crypto-probe'))], input='hpack '+encoded.hex()+'\n', text=True, capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout), dict(fields))
        result = subprocess.run([os.environ.get('VPN_CORE_CRYPTO_PROBE',str(ROOT/'bin/crypto-probe'))], input='huffman ffffffff\n', text=True, capture_output=True, check=True)
        self.assertTrue(result.stdout.startswith('ERROR:'))

    def test_03_vless_raw(self): self.exchange('vless')
    def test_04_shadowsocks_aes128(self): self.exchange('ss', 'aes-128-gcm')
    def test_05_shadowsocks_aes256(self): self.exchange('ss', 'aes-256-gcm')
    def test_06_shadowsocks_chacha(self): self.exchange('ss', 'chacha20-ietf-poly1305')
    def test_07_vmess_aes(self): self.exchange('vmess', 'aes-128-gcm')
    def test_08_vmess_chacha(self): self.exchange('vmess', 'chacha20-poly1305')
    def test_09_vmess_none(self): self.exchange('vmess', 'none')
    def test_10_websocket(self): self.exchange('vless', transport='websocket')
    def test_11_httpupgrade(self): self.exchange('vless', transport='httpupgrade')
    def test_12_grpc_flow_control(self): self.exchange('vless', transport='grpc', length=3*1024*1024)
    def test_13_tls13_grpc(self): self.exchange('vless', transport='grpc', tls=True)
    def test_14_tls13_websocket(self): self.exchange('vmess', 'aes-128-gcm', transport='websocket', tls=True)
    def test_18_trojan_websocket(self): self.exchange('trojan', transport='websocket', tls=True)
    def test_19_trojan_grpc(self): self.exchange('trojan', transport='grpc', tls=True)
    def test_20_vmess_grpc(self): self.exchange('vmess', 'chacha20-poly1305', transport='grpc')
    def test_15_bad_aead_tags(self):
        for protocol, cipher in [('ss','aes-128-gcm'), ('ss','chacha20-ietf-poly1305'), ('vmess','aes-128-gcm')]:
            peer = Peer(protocol, cipher, corrupt=True)
            try:
                with self.core(self.uri(peer)) as (port, log):
                    with self.socks(port) as s:
                        try: self.assertEqual(s.recv(100), b'')
                        except ConnectionResetError: pass
                    time.sleep(.03)
                    self.assertIn('_AUTH"', log.read_text());self.assertIn('PROTOCOL_FAILED', log.read_text())
                self.assertEqual(peer.errors, [])
            finally: peer.close()

    def test_16_grpc_custom_path(self):
        peer = Peer('vless', transport='grpc', path='/my/service/custom')
        try:
            uri = self.uri(peer).replace('serviceName=test', 'serviceName=%2Fmy%2Fservice%2Fcustom')
            with self.core(uri) as (port, _):
                with self.socks(port) as s: self.assertEqual(exact(s, len(HELLO)), HELLO)
            self.assertEqual(peer.errors, [])
        finally: peer.close()

    def test_21_grpc_multi_hunk(self):
        peer = Peer('vless', transport='grpc', path='/test/TunMulti')
        try:
            with self.core(self.uri(peer)+'&mode=multi') as (port, _):
                with self.socks(port) as s:
                    self.assertEqual(exact(s,len(HELLO)),HELLO)
                    s.sendall(b'multiple hunks')
                    self.assertEqual(exact(s,14),b'multiple hunks')
            self.assertEqual(peer.errors,[])
        finally: peer.close()

    def test_17_multiple_nodes_parallel(self):
        def run(item):
            self.exchange(*item)
        cases = [('vless','','raw'), ('vmess','aes-128-gcm','websocket'), ('ss','aes-128-gcm','raw'), ('ss','chacha20-ietf-poly1305','raw'), ('vless','','httpupgrade'), ('vless','','grpc'), ('vmess','none','raw'), ('vmess','chacha20-poly1305','raw')]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(run, cases))

if __name__ == '__main__': unittest.main(verbosity=2)
