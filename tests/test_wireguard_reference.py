"""Independent WireGuard Noise_IK and encrypted IPv4 TCP/UDP peer.

Uses the published wire specification and Python cryptography, not wireguard-go.
Every key/profile is generated locally. No OS adapter or route is changed.
"""
import base64
import contextlib
import hashlib
import hmac
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from test_core import BIN, free_port


def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def private(key):
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def digest(data):
    return hashlib.blake2s(data).digest()


def hm(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def kdf(key, data, count):
    temp = hm(key, data)
    result = []
    previous = b''
    for n in range(1, count + 1):
        previous = hm(temp, previous + bytes([n])); result.append(previous)
    return result


def mac(key, data):
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ipv4(source, target, proto, body):
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 1, 0, 64, proto, 0,
                         socket.inet_aton(source), socket.inet_aton(target))
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return header + body


def tcp_packet(target_port, sequence, acknowledgement, flags, payload=b''):
    header = struct.pack('!HHIIBBHHH', 34568, target_port, sequence, acknowledgement, 0x50, flags, 65535, 0, 0)
    pseudo = socket.inet_aton('10.71.0.2') + socket.inet_aton('127.0.0.1') + struct.pack('!BBH', 0, 6, len(header) + len(payload))
    header = header[:16] + struct.pack('!H', checksum(pseudo + header + payload)) + header[18:]
    return ipv4('10.71.0.2', '127.0.0.1', 6, header + payload)


class NoisePeer:
    def __init__(self, endpoint, key, remote, psk=b'\x00' * 32):
        self.endpoint, self.key, self.remote, self.psk = endpoint, key, remote, psk
        self.socket = socket.socket(type=socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0)); self.socket.settimeout(2)
        self.tx_counter = 0

    def close(self):
        self.socket.close()

    def initiation(self):
        ephemeral = X25519PrivateKey.generate()
        chaining = digest(b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s')
        hashed = digest(digest(chaining + b'WireGuard v1 zx2c4 Jason@zx2c4.com') + self.remote)
        ep = public(ephemeral); hashed = digest(hashed + ep)
        chaining = kdf(chaining, ep, 1)[0]
        chaining, key = kdf(chaining, ephemeral.exchange(X25519PublicKey.from_public_bytes(self.remote)), 2)
        static = ChaCha20Poly1305(key).encrypt(b'\x00' * 12, public(self.key), hashed)
        hashed = digest(hashed + static)
        chaining, key = kdf(chaining, self.key.exchange(X25519PublicKey.from_public_bytes(self.remote)), 2)
        now = time.time_ns(); stamp = struct.pack('!QI', now // 1_000_000_000 + 0x400000000000000A, now % 1_000_000_000)
        encrypted_stamp = ChaCha20Poly1305(key).encrypt(b'\x00' * 12, stamp, hashed)
        hashed = digest(hashed + encrypted_stamp)
        message = struct.pack('<II', 1, 123456) + ep + static + encrypted_stamp
        message += mac(digest(b'mac1----' + self.remote), message) + b'\x00' * 16
        self.chaining, self.hashed, self.ephemeral = chaining, hashed, ephemeral
        return message

    def handshake(self):
        self.socket.sendto(self.initiation(), self.endpoint)
        response, _ = self.socket.recvfrom(65535)
        if len(response) != 92 or struct.unpack_from('<I', response)[0] != 2 or struct.unpack_from('<I', response, 8)[0] != 123456:
            raise ValueError('invalid response framing')
        if not hmac.compare_digest(response[60:76], mac(digest(b'mac1----' + public(self.key)), response[:60])):
            raise ValueError('invalid responder MAC')
        ep = response[12:44]
        hashed = digest(self.hashed + ep)
        chaining = kdf(self.chaining, ep, 1)[0]
        remote_ep = X25519PublicKey.from_public_bytes(ep)
        chaining = kdf(chaining, self.ephemeral.exchange(remote_ep), 1)[0]
        chaining = kdf(chaining, self.key.exchange(remote_ep), 1)[0]
        chaining, temp, key = kdf(chaining, self.psk, 3)
        hashed = digest(hashed + temp)
        if ChaCha20Poly1305(key).decrypt(b'\x00' * 12, response[44:60], hashed) != b'':
            raise ValueError('invalid response plaintext')
        self.send_key, self.receive_key = kdf(chaining, b'', 2)
        self.receiver = struct.unpack_from('<I', response, 4)[0]
        self.send_packet(b'')  # key confirmation

    def send_packet(self, packet):
        header = struct.pack('<IIQ', 4, self.receiver, self.tx_counter)
        nonce = struct.pack('<IQ', 0, self.tx_counter)
        self.tx_counter += 1
        padded = packet + b'\x00' * ((-len(packet)) % 16)
        self.socket.sendto(header + ChaCha20Poly1305(self.send_key).encrypt(nonce, padded, b''), self.endpoint)

    def receive_packet(self):
        while True:
            data, _ = self.socket.recvfrom(65535)
            if len(data) < 32 or struct.unpack_from('<I', data)[0] != 4:
                continue
            if struct.unpack_from('<I', data, 4)[0] != 123456:
                raise ValueError('wrong receiver index')
            nonce = b'\x00' * 4 + data[8:16]
            plain = ChaCha20Poly1305(self.receive_key).decrypt(nonce, data[16:], b'')
            if not plain:
                continue
            if plain[0] >> 4 != 4:
                raise ValueError('unexpected IP family')
            return plain[:struct.unpack_from('!H', plain, 2)[0]]


class WireGuardReferenceTests(unittest.TestCase):
    @contextlib.contextmanager
    def server(self):
        server_key, client_key = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        port = free_port()
        config = {'outbounds': [{'tag': 'direct', 'uri': 'direct://'}], 'final': 'direct',
                  'inbounds': [{'protocol': 'wireguard', 'listen': f'127.0.0.1:{port}', 'wireguard': {
                      'private_key': base64.b64encode(private(server_key)).decode(), 'peers': [{
                          'public_key': base64.b64encode(public(client_key)).decode(), 'allowed_ips': ['10.71.0.2/32']}]
                  }}]}
        with tempfile.TemporaryDirectory(prefix='vpn-wireguard-reference-') as temp:
            root = pathlib.Path(temp); path = root / 'server.json'; path.write_text(json.dumps(config), encoding='utf-8')
            with (root / 'server.log').open('w') as log:
                process = subprocess.Popen([str(BIN), '--config', str(path), '--no-socks'], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 5
                    while 'Server listening on' not in (root / 'server.log').read_text(errors='replace'):
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail('WireGuard server readiness failed')
                        time.sleep(.02)
                    peer = NoisePeer(('127.0.0.1', port), client_key, public(server_key))
                    try:
                        yield peer
                    finally:
                        peer.close()
                except BaseException as error:
                    log.flush(); error.add_note((root / 'server.log').read_text(errors='replace')[-3000:]); raise
                finally:
                    if process.poll() is None: process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)

    def test_noise_and_encrypted_udp_payload_and_source_guard(self):
        with self.server() as peer, socket.socket(type=socket.SOCK_DGRAM) as echo:
            echo.bind(('127.0.0.1', 0)); echo.settimeout(.2)
            stop = threading.Event()
            def worker():
                while not stop.is_set():
                    try:
                        body, a = echo.recvfrom(65535); echo.sendto(body, a)
                    except (TimeoutError, OSError):
                        continue
            thread = threading.Thread(target=worker); thread.start()
            try:
                peer.handshake()
                for size in [32, 1000]:
                    body = b'independently encrypted WireGuard\x00\xff' * 32
                    body = body[:size]
                    udp = struct.pack('!HHHH', 34567, echo.getsockname()[1], len(body) + 8, 0) + body
                    peer.send_packet(ipv4('10.71.0.2', '127.0.0.1', 17, udp))
                    packet = peer.receive_packet()
                    self.assertEqual(packet[9], 17); self.assertEqual(packet[28:], body)
                    self.assertEqual(packet[16:20], socket.inet_aton('10.71.0.2'))
                # A valid encryption key does not authorize an unlisted source IP.
                peer.send_packet(ipv4('10.72.0.2', '127.0.0.1', 17, udp))
                peer.socket.settimeout(.3)
                with self.assertRaises(TimeoutError): peer.receive_packet()
            finally:
                stop.set(); thread.join(timeout=2); self.assertFalse(thread.is_alive())

    def test_noise_and_encrypted_tcp_payload(self):
        with self.server() as peer, socket.socket() as echo:
            echo.bind(('127.0.0.1', 0)); echo.listen(); echo.settimeout(5)
            errors = []
            def worker():
                try:
                    conn, _ = echo.accept()
                    with conn:
                        conn.settimeout(5)
                        while body := conn.recv(65535): conn.sendall(body)
                except OSError: pass
                except BaseException as e: errors.append(e)
            thread = threading.Thread(target=worker); thread.start()
            try:
                peer.handshake(); port = echo.getsockname()[1]; peer.send_packet(tcp_packet(port, 1000, 0, 2))
                packet = peer.receive_packet(); self.assertEqual(packet[9], 6)
                self.assertEqual(packet[33] & 0x12, 0x12); server_seq = struct.unpack_from('!I', packet, 24)[0]
                self.assertEqual(struct.unpack_from('!I', packet, 28)[0], 1001)
                peer.send_packet(tcp_packet(port, 1001, server_seq + 1, 16))
                body = b'WireGuard independent TCP payload\x00\xff'
                peer.send_packet(tcp_packet(port, 1001, server_seq + 1, 24, body))
                received = b''
                while len(received) < len(body):
                    packet = peer.receive_packet(); offset = (packet[32] >> 4) * 4 + 20
                    received += packet[offset:]
                self.assertEqual(received, body)
                peer.send_packet(tcp_packet(port, 1001 + len(body), server_seq + 1 + len(body), 20))
            finally:
                thread.join(timeout=6); self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])

    def test_noise_rejects_unknown_identity_and_corrupt_mac(self):
        with self.server() as peer:
            message = bytearray(peer.initiation()); message[116] ^= 1
            peer.socket.settimeout(.3); peer.socket.sendto(message, peer.endpoint)
            with self.assertRaises(TimeoutError): peer.socket.recvfrom(65535)
            unknown = NoisePeer(peer.endpoint, X25519PrivateKey.generate(), peer.remote)
            try:
                unknown.socket.settimeout(.3)
                with self.assertRaises(TimeoutError): unknown.handshake()
            finally: unknown.close()
