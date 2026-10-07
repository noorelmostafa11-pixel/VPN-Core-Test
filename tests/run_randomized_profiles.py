"""Exercise 256 fixed seeds per randomized preset against independent OpenSSL."""
import argparse
import os
import socket
import ssl
import subprocess
import threading
from test_core import CoreTests, ROOT


def run(go):
    CoreTests.setUpClass()
    try:
        for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(CoreTests.cert, CoreTests.key)
            context.minimum_version = context.maximum_version = version
            context.set_alpn_protocols(['http/1.1'])
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(32)
            listener.settimeout(.2)
            stop = threading.Event()
            workers = []

            def handle(raw):
                try:
                    raw.settimeout(5)
                    with context.wrap_socket(raw, server_side=True) as connection:
                        while True:
                            data = connection.recv(1024)
                            if not data:
                                break
                            connection.sendall(data)
                except (OSError, ssl.SSLError):
                    pass  # The Go client fails the test for a handshake or IO error.
                finally:
                    raw.close()

            def accept():
                while not stop.is_set():
                    try:
                        raw, _ = listener.accept()
                    except socket.timeout:
                        continue
                    worker = threading.Thread(target=handle, args=(raw,), daemon=True)
                    workers.append(worker)
                    worker.start()

            thread = threading.Thread(target=accept)
            thread.start()
            try:
                env = dict(os.environ, GOTOOLCHAIN='local',
                           VPN_CORE_TLS_TEST_SERVER='127.0.0.1:' + str(listener.getsockname()[1]),
                           VPN_CORE_TLS_TEST_CA=str(CoreTests.ca))
                subprocess.run([go, 'test', '-mod=vendor', '-race', '-run',
                                '^TestRandomizedOpenSSLProfiles$', '-v', '-count=1', '.'],
                               cwd=ROOT / 'tls-provider', env=env, check=True, timeout=180)
                print(f'PASS: {version.name}, 512 seeded randomized TLS handshakes and matching echoes', flush=True)
            finally:
                stop.set()
                thread.join(2)
                listener.close()
                for worker in workers:
                    worker.join(6)
    finally:
        CoreTests.tearDownClass()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default=os.environ.get('VPN_CORE_GO', 'go'))
    run(parser.parse_args().go)
