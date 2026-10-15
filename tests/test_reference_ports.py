"""Live-kernel ownership controls for independent reference fixture endpoints."""
import socket
import threading
import unittest
from unittest import mock

from test_core import exact
import test_server_reference as serverref
from test_server_reference import reserve_reference_ports


class ReferencePortTests(unittest.TestCase):
    def test_distinct_reserved_endpoints_and_handoff(self):
        for http3 in [False, True]:
            with self.subTest(http3=http3), reserve_reference_ports(http3) as (server, socks):
                server_port, socks_port = server.getsockname()[1], socks.getsockname()[1]
                self.assertNotEqual(server_port, socks_port)
                kind = socket.SOCK_DGRAM if http3 else socket.SOCK_STREAM
                for port, socket_type in [(server_port, kind), (socks_port, socket.SOCK_STREAM)]:
                    with socket.socket(type=socket_type) as contender:
                        with self.assertRaises(OSError):
                            contender.bind(('127.0.0.1', port))
                # Native server takes ownership first; reference endpoint stays reserved.
                server.close()
                with socket.socket(type=kind) as native:
                    native.bind(('127.0.0.1', server_port))
                    with socket.socket() as contender:
                        with self.assertRaises(OSError):
                            contender.bind(('127.0.0.1', socks_port))
                    socks.close()
                    with socket.socket() as reference:
                        reference.bind(('127.0.0.1', socks_port))

    def test_reservations_release_on_failure(self):
        for http3 in [False, True]:
            with self.subTest(http3=http3):
                with self.assertRaisesRegex(RuntimeError, 'injected'):
                    with reserve_reference_ports(http3) as (server, socks):
                        server_port, socks_port = server.getsockname()[1], socks.getsockname()[1]
                        raise RuntimeError('injected')
                for port, kind in [(server_port, socket.SOCK_DGRAM if http3 else socket.SOCK_STREAM),
                                   (socks_port, socket.SOCK_STREAM)]:
                    with socket.socket(type=kind) as released:
                        released.bind(('127.0.0.1', port))


class ReferencePairPortTests(unittest.TestCase):
    setUpClass = classmethod(serverref.ServerReferenceTests.setUpClass.__func__)
    tearDownClass = classmethod(serverref.ServerReferenceTests.tearDownClass.__func__)
    socks = serverref.ServerReferenceTests.socks
    wait_port = serverref.ServerReferenceTests.wait_port
    reference_pair = serverref.ServerReferenceTests.reference_pair

    def test_released_selector_alias_cannot_merge_native_and_socks(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(8)
        def echo():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(8)
                    while body := connection.recv(65535):
                        connection.sendall(body)
            except OSError:
                pass
        worker = threading.Thread(target=echo); worker.start()
        try:
            # The previous fixture called this released selector twice and
            # mistook the native TLS listener for SOCKS readiness.
            alias = serverref.free_port()
            with mock.patch.object(serverref, 'free_port', return_value=alias):
                with self.reference_pair('vmess', secure=True, inspect_http=True,
                     transport={'type': 'xhttp', 'path': '/vpn', 'host': 'localhost',
                                'mode': 'packet-up', 'alpn': ['http/1.1']}) as (socks, server):
                    self.assertNotEqual(server, socks)
                    connection, _ = self.socks(socks, 1, listener.getsockname())
                    with connection:
                        connection.settimeout(8)
                        first = b'authenticated fixture exchange'
                        connection.sendall(first)
                        self.assertEqual(exact(connection, len(first)), first)
                        body = b'\x00reference port ownership\xff' * 8000
                        connection.sendall(body)
                        self.assertEqual(exact(connection, len(body)), body)
        finally:
            listener.close(); worker.join(timeout=10)
            self.assertFalse(worker.is_alive())
