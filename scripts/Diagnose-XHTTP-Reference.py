"""Bounded synthetic Trojan/XHTTP diagnosis; never runs private/public nodes."""
import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--attempts', type=int, default=32)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--trace-proxy', type=pathlib.Path, required=True)
parser.add_argument('--skip-matrix', action='store_true', help='local observer smoke only')
ARGS = parser.parse_args()
if not 1 <= ARGS.attempts <= 64:
    parser.error('attempts must be 1..64')
ARGS.output.mkdir(parents=True, exist_ok=True)
ARGS.trace_proxy = ARGS.trace_proxy.resolve()
sys.path.insert(0, str(ROOT / 'tests'))
from test_core import exact
from test_xhttp_server_reference import XHTTPServerReferenceTests

ECHOES, TRACES = [], []
SYNTHETIC_HEADER = hashlib.sha224(b'synthetic-reference-server-password').hexdigest().encode()


@contextlib.contextmanager
def trace_xray(test):
    """Add a separately verified TLS hop only to synthetic Trojan HTTP1 peers."""
    launch = subprocess.Popen
    processes, streams = [], []
    def observed_launch(command, *args, **kwargs):
        if str(command[0]) == str(test.xray) and '-config' in command:
            config_path = pathlib.Path(command[command.index('-config') + 1])
            config = json.loads(config_path.read_text(encoding='utf-8'))
            outbound = config['outbounds'][0]
            stream = outbound.get('streamSettings', {})
            if outbound['protocol'] == 'trojan' and stream.get('network') == 'xhttp' and stream.get('tlsSettings', {}).get('alpn') == ['http/1.1']:
                server = outbound['settings']['servers'][0]
                path = ARGS.output / f'packet-trace-{len(TRACES):04d}.jsonl'
                TRACES.append(path)
                output = path.open('w', encoding='utf-8')
                error = tempfile.TemporaryFile(mode='w+', encoding='utf-8')
                streams.extend([output, error])
                proxy = launch([str(ARGS.trace_proxy), '-target', f'https://127.0.0.1:{server["port"]}',
                                '-cert', str(test.cert), '-key', str(test.key)], stdout=output, stderr=error)
                processes.append(proxy)
                deadline = time.monotonic() + 5
                while True:
                    line = path.read_text(encoding='utf-8').splitlines()
                    if line:
                        server['port'] = int(json.loads(line[0])['listen'].rsplit(':', 1)[1])
                        break
                    if proxy.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('diagnostic TLS hop failed readiness')
                    time.sleep(.01)
                config_path.write_text(json.dumps(config), encoding='utf-8')
        return launch(command, *args, **kwargs)
    try:
        with mock.patch.object(subprocess, 'Popen', observed_launch):
            yield
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
        for stream in streams:
            stream.close()


class Diagnostic(XHTTPServerReferenceTests):
    def exchanges(self, traced):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(.2)
        stop, handlers = threading.Event(), []
        def echo(connection):
            digest, count, tail, headers = hashlib.sha256(), 0, b'', []
            try:
                with connection:
                    connection.settimeout(8)
                    while data := connection.recv(65535):
                        merged = tail + data
                        index = merged.find(SYNTHETIC_HEADER)
                        if index >= 0:
                            headers.append(count - len(tail) + index)
                        tail = merged[-55:]
                        digest.update(data); count += len(data)
                        connection.sendall(data)
            except OSError:
                pass
            finally:
                ECHOES.append({'traced': traced, 'bytes': count, 'sha256': digest.hexdigest(), 'trojan_header_offsets': headers})
        def accept():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except OSError:
                    continue
                worker = threading.Thread(target=echo, args=(connection,))
                handlers.append(worker); worker.start()
        worker = threading.Thread(target=accept); worker.start()
        extra = {'sessionIDPlacement': 'header', 'sessionIDKey': 'Meta-Session',
                 'seqPlacement': 'query', 'seqKey': 'Meta-Sequence'}
        try:
            for attempt in range(ARGS.attempts):
                observation = trace_xray(self) if traced else contextlib.nullcontext()
                with observation, self.reference_pair('trojan', transport={'type': 'xhttp', 'path': '/vpn path',
                       'host': 'localhost', 'mode': 'packet-up', 'alpn': ['http/1.1'], 'extra': extra}) as socks:
                    for cycle in range(2):
                        with self.subTest(traced=traced, attempt=attempt, cycle=cycle):
                            connection, _ = self.socks(socks, 1, listener.getsockname())
                            with connection:
                                connection.settimeout(8)
                                if attempt % 2:
                                    # Exercise both sides of Xray's initial 100 ms read.
                                    time.sleep(.15)
                                for phase, body in [('first', b'XHTTP Trojan authenticated first body'),
                                                    ('large', bytes([91 + cycle]) * 200001)]:
                                    connection.sendall(body)
                                    got = exact(connection, len(body))
                                    if got != body:
                                        offset = next(i for i, pair in enumerate(zip(got, body)) if pair[0] != pair[1])
                                        self.fail(json.dumps({'phase': phase, 'offset': offset,
                                                  'expected_sha256': hashlib.sha256(body).hexdigest(),
                                                  'received_sha256': hashlib.sha256(got).hexdigest(),
                                                  'starts_trojan_header': got.startswith(SYNTHETIC_HEADER)}))
        finally:
            stop.set(); listener.close(); worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            for handler in handlers:
                handler.join(timeout=10); self.assertFalse(handler.is_alive())

    def test_direct_fresh_processes(self):
        self.exchanges(False)

    def test_observed_fresh_processes(self):
        self.exchanges(True)

    def test_original_metadata_matrix_with_selected_observation(self):
        with trace_xray(self):
            self.test_xray_metadata_placements_and_keys()


names = ['test_direct_fresh_processes', 'test_observed_fresh_processes']
if not ARGS.skip_matrix:
    names.append('test_original_metadata_matrix_with_selected_observation')
result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Diagnostic(name) for name in names))
summary = {'schema': 'xhttp-reference-diagnostic-v1', 'platform': platform.platform(),
           'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
           'attempts_per_path': ARGS.attempts, 'tests_run': result.testsRun,
           'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
           'trace_files': len(TRACES), 'echoes': ECHOES,
           'boundary': 'Synthetic loopback diagnostic only; observed path includes an extra verified TLS hop. No real-node/host-network acceptance.'}
(ARGS.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
if result.skipped:
    raise SystemExit('Required independent reference missing; diagnostic is incomplete')
raise SystemExit(not result.wasSuccessful())
