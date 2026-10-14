"""Official V2Ray 4.45.2 HTTP/2 client to synthetic Go protocol listeners."""
import os
import pathlib
import socket
import subprocess
import threading
import unittest

from test_core import exact
import test_server_reference as serverref


class HTTP2ServerReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidate = pathlib.Path(os.environ.get('VPN_CORE_REFERENCE_V2RAY4', ''))
        if not candidate.is_file():
            raise unittest.SkipTest('set VPN_CORE_REFERENCE_V2RAY4 for the independent legacy HTTP/2 client')
        cls.v2ray = candidate
        cls.v2ray_version = subprocess.check_output([str(candidate), '-version'], text=True).splitlines()[0]
        serverref.ServerReferenceTests.setUpClass.__func__(cls)

    tearDownClass = classmethod(serverref.ServerReferenceTests.tearDownClass.__func__)
    socks = serverref.ServerReferenceTests.socks
    wait_port = serverref.ServerReferenceTests.wait_port
    reference_pair = serverref.ServerReferenceTests.reference_pair

    def test_v2ray_http2_four_protocols_and_custom_method(self):
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
                for method in ['PUT', 'POST']:
                    with self.subTest(protocol=protocol, method=method):
                        cipher = 'aes-128-gcm' if protocol == 'vmess' else 'aes-256-gcm'
                        with self.reference_pair(protocol, cipher=cipher, secure=True, legacy=self.v2ray,
                                                 transport={'type': 'http2', 'path': '/vpn path', 'host': 'localhost', 'method': method}) as socks:
                            for cycle in range(8):
                                c, _ = self.socks(socks, 1, listener.getsockname())
                                with c:
                                    c.settimeout(8)
                                    if protocol == 'trojan':
                                        first = b'HTTP2 Trojan authenticated first body'
                                        c.sendall(first); self.assertEqual(exact(c, len(first)), first)
                                    body = bytes([cycle + 71]) * 200001
                                    c.sendall(body); self.assertEqual(exact(c, len(body)), body)
        finally:
            stop.set(); listener.close(); worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            for handler in handlers:
                handler.join(timeout=10); self.assertFalse(handler.is_alive())


if __name__ == '__main__':
    unittest.main(verbosity=2)
