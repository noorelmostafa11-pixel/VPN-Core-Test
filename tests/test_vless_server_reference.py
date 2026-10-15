"""Official Xray Vision client against the project TLS server, synthetic only."""
import socket
import ssl
import threading
import unittest
import base64
from cryptography.hazmat.primitives.asymmetric import x25519

from test_core import exact
import test_server_reference as serverref


class VLESSVisionReferenceTests(unittest.TestCase):
    setUpClass = classmethod(serverref.ServerReferenceTests.setUpClass.__func__)
    tearDownClass = classmethod(serverref.ServerReferenceTests.tearDownClass.__func__)
    socks = serverref.ServerReferenceTests.socks
    wait_port = serverref.ServerReferenceTests.wait_port
    reference_pair = serverref.ServerReferenceTests.reference_pair

    def test_xray_vless_vision_plain_inner_tls_and_xudp(self):
        self.payload_cases()

    def test_xray_vless_reality_vision_and_plain_flow_payload(self):
        for flow in ['', 'xtls-rprx-vision']:
            with self.subTest(flow=flow):
                self.payload_cases(flow=flow, use_reality=True)

    def payload_cases(self, flow='xtls-rprx-vision', use_reality=False, secure=True, decryption=None, encryption=None, transport=None, grpc_multi=False):
        for inner_tls in [False, True]:
            with self.subTest(inner_tls=inner_tls):
                tcp, udp = socket.socket(), socket.socket(type=socket.SOCK_DGRAM)
                tcp.bind(('127.0.0.1', 0)); tcp.listen(); tcp.settimeout(.2)
                udp.bind(('127.0.0.1', 0)); udp.settimeout(.2)
                tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls_context.minimum_version = tls_context.maximum_version = ssl.TLSVersion.TLSv1_3
                tls_context.load_cert_chain(self.cert, self.key)
                stop, connections = threading.Event(), []
                def handle(connection):
                    try:
                        with connection:
                            connection.settimeout(8)
                            wire = tls_context.wrap_socket(connection, server_side=True) if inner_tls else connection
                            with wire:
                                while data := wire.recv(65535): wire.sendall(data)
                    except (OSError, ssl.SSLError):
                        pass
                def accept():
                    while not stop.is_set():
                        try: connection, _ = tcp.accept()
                        except OSError: continue
                        worker = threading.Thread(target=handle, args=(connection,))
                        connections.append(worker); worker.start()
                def echo_udp():
                    while not stop.is_set():
                        try: data, address = udp.recvfrom(65535); udp.sendto(data, address)
                        except OSError: continue
                listeners = [threading.Thread(target=accept), threading.Thread(target=echo_udp)]
                for worker in listeners: worker.start()
                decoy = None
                try:
                    reality = None
                    if use_reality:
                        import http.server
                        decoy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler)
                        decoy.socket = tls_context.wrap_socket(decoy.socket, server_side=True)
                        decoy_thread = threading.Thread(target=decoy.serve_forever)
                        decoy_thread.start()
                        private = x25519.X25519PrivateKey.generate().private_bytes_raw()
                        reality = {'private_key': base64.urlsafe_b64encode(private).decode().rstrip('='),
                                   'server_names': ['localhost'], 'short_ids': ['a1b2c3d4'],
                                   'target': f'127.0.0.1:{decoy.server_port}'}
                    with self.reference_pair('vless', secure=secure, flow=flow, reality=reality, decryption=decryption, encryption=encryption, transport=transport, grpc_multi=grpc_multi) as socks:
                        context = ssl.create_default_context(cafile=self.cert)
                        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                        for cycle in range(16):
                            c, _ = self.socks(socks, 1, tcp.getsockname())
                            with c:
                                c.settimeout(8)
                                wire = context.wrap_socket(c, server_hostname='localhost') if inner_tls else c
                                with wire:
                                    body = bytes([cycle + 31]) * 200001
                                    wire.sendall(body)
                                    self.assertEqual(exact(wire, len(body)), body)
                        for cycle in range(8):
                            control, relay = self.socks(socks, 3, ('0.0.0.0', 0))
                            with control, socket.socket(type=socket.SOCK_DGRAM) as client:
                                client.bind(('127.0.0.1', 0)); client.settimeout(8)
                                header = b'\0\0\0\1' + socket.inet_aton('127.0.0.1') + udp.getsockname()[1].to_bytes(2, 'big')
                                for size in [32, 1400, 3800]:
                                    body = bytes([cycle + 11]) * size
                                    client.sendto(header + body, relay)
                                    reply, _ = client.recvfrom(65535)
                                    self.assertEqual(reply[10:], body)
                finally:
                    if decoy:
                        decoy.shutdown(); decoy.server_close(); decoy_thread.join(timeout=5)
                        self.assertFalse(decoy_thread.is_alive())
                    stop.set(); tcp.close(); udp.close()
                    for worker in [*listeners, *connections]:
                        worker.join(timeout=10)
                        self.assertFalse(worker.is_alive(), 'reference worker retained')

    def test_xray_vless_vision_missing_tcp_flow_rejected(self):
        with socket.socket() as destination:
            destination.bind(('127.0.0.1', 0)); destination.listen(); destination.settimeout(.3)
            with self.reference_pair('vless', secure=True, server_flow='xtls-rprx-vision') as socks:
                c, _ = self.socks(socks, 1, destination.getsockname())
                with c:
                    c.settimeout(3)
                    c.sendall(b'flow policy must reject this TCP request')
                    try:
                        self.assertEqual(c.recv(1), b'')
                    except OSError:
                        pass
                with self.assertRaises(socket.timeout):
                    destination.accept()
