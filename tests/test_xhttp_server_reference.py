"""Pinned Xray XHTTP stream-one client against synthetic native Go servers."""
import base64
import socket
import threading
import unittest
from cryptography.hazmat.primitives.asymmetric import x25519

from test_core import exact
import test_server_reference as serverref
import test_vless_server_reference as visionref


class XHTTPServerReferenceTests(unittest.TestCase):
    setUpClass = classmethod(serverref.ServerReferenceTests.setUpClass.__func__)
    tearDownClass = classmethod(serverref.ServerReferenceTests.tearDownClass.__func__)
    socks = serverref.ServerReferenceTests.socks
    wait_port = serverref.ServerReferenceTests.wait_port
    reference_pair = serverref.ServerReferenceTests.reference_pair
    payload_cases = visionref.VLESSVisionReferenceTests.payload_cases

    def test_xray_stream_one_four_protocols_http1_http2_and_cleartext(self):
        self.four_protocol_matrix('stream-one')

    def test_xray_split_four_protocols_http1_http2_and_cleartext(self):
        for mode in ['stream-up', 'packet-up', 'auto']:
            with self.subTest(mode=mode):
                self.four_protocol_matrix(mode)

    def test_xray_http3_four_protocols_all_modes(self):
        for mode in ['stream-one', 'stream-up', 'packet-up', 'auto']:
            with self.subTest(mode=mode):
                self.four_protocol_matrix(mode, http3=True)

    def four_protocol_matrix(self, mode, http3=False, extra=None, cycles=8):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(.2)
        stop, handlers = threading.Event(), []
        def handle(connection):
            try:
                with connection:
                    connection.settimeout(8)
                    while body := connection.recv(65535): connection.sendall(body)
            except OSError: pass
        def accept():
            while not stop.is_set():
                try: connection, _ = listener.accept()
                except OSError: continue
                worker = threading.Thread(target=handle, args=(connection,))
                handlers.append(worker); worker.start()
        worker = threading.Thread(target=accept); worker.start()
        try:
            for protocol in ['vless', 'vmess', 'trojan', 'ss']:
                for secure, alpn in ([(True, ['h3'])] if http3 else [(False, ['http/1.1']), (True, ['http/1.1']), (True, ['h2'])]):
                    with self.subTest(protocol=protocol, tls=secure, alpn=alpn):
                        cipher = 'aes-128-gcm' if protocol == 'vmess' else 'aes-256-gcm'
                        with self.reference_pair(protocol, cipher=cipher, secure=secure,
                                                 transport={'type': 'xhttp', 'path': '/vpn path', 'host': 'localhost', 'mode': mode, 'alpn': alpn, **({'extra': extra} if extra else {})}) as socks:
                            for cycle in range(cycles):
                                c, _ = self.socks(socks, 1, listener.getsockname())
                                with c:
                                    c.settimeout(8)
                                    if protocol == 'trojan':
                                        first = b'XHTTP Trojan authenticated first body'
                                        c.sendall(first); self.assertEqual(exact(c, len(first)), first)
                                    body = bytes([cycle + 91]) * 200001
                                    c.sendall(body); self.assertEqual(exact(c, len(body)), body)
        finally:
            stop.set(); listener.close(); worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            for handler in handlers:
                handler.join(timeout=10); self.assertFalse(handler.is_alive())

    def test_xray_metadata_placements_and_keys(self):
        for session, seq in [('query', 'header'), ('header', 'query'), ('cookie', 'cookie'), ('path', 'header'), ('header', 'path')]:
            extra = {'sessionIDPlacement': session, 'seqPlacement': seq}
            if session != 'path':
                extra['sessionIDKey'] = 'Meta-Session'
            if seq != 'path':
                extra['seqKey'] = 'Meta-Sequence'
            for http3 in [False, True]:
                with self.subTest(session=session, seq=seq, http3=http3):
                    self.four_protocol_matrix('packet-up', http3=http3, extra=extra, cycles=2)

    def test_xray_stream_one_hybrid_vision_inner_tls_xudp(self):
        private = x25519.X25519PrivateKey.generate()
        secret = base64.urlsafe_b64encode(private.private_bytes_raw()).decode().rstrip('=')
        public = base64.urlsafe_b64encode(private.public_key().public_bytes_raw()).decode().rstrip('=')
        for mode, alpn in [('native', ['h2']), ('random', ['http/1.1'])]:
            with self.subTest(mode=mode, alpn=alpn):
                decryption = '.'.join(['mlkem768x25519plus', mode, '60-60s', '100-75-75', secret])
                encryption = '.'.join(['mlkem768x25519plus', mode, '0rtt', '100-75-75', public])
                self.payload_cases(decryption=decryption, encryption=encryption,
                                   transport={'type': 'xhttp', 'path': '/vpn', 'host': 'localhost', 'mode': 'stream-one', 'alpn': alpn})

    def test_xray_split_hybrid_vision_inner_tls_xudp(self):
        private = x25519.X25519PrivateKey.generate()
        secret = base64.urlsafe_b64encode(private.private_bytes_raw()).decode().rstrip('=')
        public = base64.urlsafe_b64encode(private.public_key().public_bytes_raw()).decode().rstrip('=')
        for transport_mode in ['stream-up', 'packet-up']:
            for cipher_mode, alpn in [('native', ['h2']), ('random', ['http/1.1'])]:
                with self.subTest(mode=transport_mode, cipher=cipher_mode, alpn=alpn):
                    decryption = '.'.join(['mlkem768x25519plus', cipher_mode, '60-60s', '100-75-75', secret])
                    encryption = '.'.join(['mlkem768x25519plus', cipher_mode, '0rtt', '100-75-75', public])
                    self.payload_cases(decryption=decryption, encryption=encryption,
                                       transport={'type': 'xhttp', 'path': '/vpn', 'host': 'localhost', 'mode': transport_mode, 'alpn': alpn})

    def test_xray_http3_hybrid_vision_inner_tls_xudp(self):
        private = x25519.X25519PrivateKey.generate()
        secret = base64.urlsafe_b64encode(private.private_bytes_raw()).decode().rstrip('=')
        public = base64.urlsafe_b64encode(private.public_key().public_bytes_raw()).decode().rstrip('=')
        for mode in ['stream-one', 'stream-up', 'packet-up']:
            with self.subTest(mode=mode):
                decryption = '.'.join(['mlkem768x25519plus', 'native', '60-60s', '100-75-75', secret])
                encryption = '.'.join(['mlkem768x25519plus', 'native', '0rtt', '100-75-75', public])
                self.payload_cases(decryption=decryption, encryption=encryption,
                                   transport={'type': 'xhttp', 'path': '/vpn', 'host': 'localhost', 'mode': mode, 'alpn': ['h3']})


if __name__ == '__main__':
    unittest.main(verbosity=2)
