"""Current Pre coverage: byte identity, actual inspection, and private reports."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from test_core import ROOT, BIN

spec = importlib.util.spec_from_file_location('pre_audit', ROOT / 'scripts/Audit-Pre-Support.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PreCoverageTests(unittest.TestCase):
    def fixture(self, root):
        auth = base64.urlsafe_b64encode(b'aes-128-gcm:private-ss-test-password').decode()
        uris = {
            'vless.txt': 'vless://12345678-1234-4567-9234-567812345678@localhost:443?security=tls&type=ws&fp=randomizednoalpn&alpn=h3,h2,http%2F1.1',
            'vmess.txt': 'vmess://12345678-1234-4567-9234-567812345678@localhost:443?security=tls&type=grpc',
            'trojan.txt': 'trojan://private-trojan-test-password@localhost:443?security=tls&type=tcp',
            'shadowsocks.txt': 'ss://' + auth + '@localhost:443?security=none',
        }
        entries = []
        for name, uri in uris.items():
            data = ('# fixture\n  ' + uri + '  \n\n').encode()
            (root / name).write_bytes(data)
            entries.append({'name': name, 'bytes': len(data), 'nodes': 1,
                            'sha256': hashlib.sha256(data).hexdigest()})
        return {'repository': 'noorelmostafa11-pixel/VPN-Nodes-Pre', 'directory': 'output/protocols',
                'commit': 'a' * 40, 'files': entries}, uris

    def test_latest_download_resolves_main_once_and_uses_that_commit_for_every_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); source = root / 'source'; source.mkdir()
            self.fixture(source)
            calls = []
            def fetch(url):
                calls.append(url)
                if url.endswith('/commits/main'):
                    return json.dumps({'sha': 'b' * 40, 'commit': {'committer': {'date': '2026-10-08T00:00:00Z'}}}).encode()
                self.assertIn('/' + 'b' * 40 + '/output/protocols/', url)
                return (source / url.rsplit('/', 1)[1]).read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                manifest = audit.snapshot.prepare_latest(root/'saved/protocols', root/'saved/manifest.json', fetch)
            self.assertEqual(sum(e['nodes'] for e in manifest['files']), 4)
            self.assertEqual(len(calls), 5)
            self.assertEqual(sum(u.endswith('/commits/main') for u in calls), 1)
            for name in audit.snapshot.NAMES:
                self.assertEqual((root/'saved/protocols'/name).read_bytes(), (source/name).read_bytes())

    def test_latest_network_summary_accepts_new_ids_and_rejects_mixed_snapshots(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); protocols = root/'snapshot/protocols'; protocols.mkdir(parents=True)
            manifest, uris = self.fixture(protocols)
            manifest_path = protocols.parent/'manifest.json'
            manifest_path.write_text(json.dumps(manifest))
            for index in range(15):
                folder = root/'reports'/str(index); folder.mkdir(parents=True)
                rows = []
                if index < 4:
                    name, uri = list(uris.items())[index]
                    rows = [{'source':name, 'node_id':hashlib.sha256(uri.encode()).hexdigest()[:20], 'status':'PASS'}]
                (folder/'results.ndjson').write_text(''.join(json.dumps(r)+'\n' for r in rows))
                (folder/'summary.json').write_text(json.dumps({'completed':True,'inventory':len(rows),
                    'selected':len(rows),'finished':len(rows),'core_sha256':'c'*64,'source_commit':'b'*40}))
                (folder/'pre-manifest.json').write_bytes(manifest_path.read_bytes())
            command = [str(ROOT/'scripts/Summarize-Network.py'), '--pre-snapshot', str(protocols.parent),
                       '--reports', str(root/'reports'), '--output', str(root/'output')]
            result = subprocess.run([sys.executable, *command], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((root/'output/network-summary.json').read_text())
            self.assertEqual(report['expected_rows'], 4)
            self.assertEqual(report['new_nodes'], 4)
            self.assertTrue(report['complete'])
            (root/'reports/0/pre-manifest.json').write_text('{}')
            result = subprocess.run([sys.executable, *command], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads((root/'output/network-summary.json').read_text())['complete'])

    def test_inspects_all_four_files_without_disclosing_uris_or_credentials(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            manifest, uris = self.fixture(root)
            output = root / 'audit'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(audit.audit(BIN, root, manifest, output), 0)
            report = json.loads((output / 'summary.json').read_text())
            self.assertEqual(report['counts'], {'SUPPORTED': 4})
            self.assertEqual(report['rows'], 4)
            self.assertFalse(report['network_test_performed'])
            rows = [json.loads(s) for s in (output / 'rows.ndjson').read_text().splitlines()]
            for row in rows:
                self.assertEqual(row['line'], 2)
                self.assertEqual(row['node_id'], hashlib.sha256(uris[row['source']].encode()).hexdigest()[:20])
            exported = ''.join(p.read_text() for p in output.iterdir())
            for uri in uris.values():
                self.assertNotIn(uri, exported)
            self.assertNotIn('private-ss-test-password', exported)
            self.assertNotIn('private-trojan-test-password', exported)

    def test_changed_source_bytes_invalidate_the_previous_success(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            manifest, _ = self.fixture(root)
            output = root / 'audit'
            output.mkdir()
            (output / 'summary.json').write_text('{"completed":true}')
            (root / 'vless.txt').write_bytes(b'changed-source\n')
            with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
                audit.audit(BIN, root, manifest, output)
            self.assertFalse((output / 'summary.json').exists())

    def test_a_regression_to_invalid_configuration_fails_the_coverage_gate(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            manifest, _ = self.fixture(root)
            manifest['expected_support'] = {'SUPPORTED': 4, 'INVALID': 0}
            path = root / 'vless.txt'
            data = path.read_bytes().replace(b'randomizednoalpn', b'unknown-test-profile')
            path.write_bytes(data)
            entry = next(e for e in manifest['files'] if e['name'] == path.name)
            entry['bytes'], entry['sha256'] = len(data), hashlib.sha256(data).hexdigest()
            output = root / 'audit'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(audit.audit(BIN, root, manifest, output), 1)
            report = json.loads((output / 'summary.json').read_text())
            self.assertTrue(report['completed'])
            self.assertFalse(report['coverage_met'])
            self.assertEqual(report['counts'], {'INVALID': 1, 'SUPPORTED': 3})

    def test_failed_download_validation_does_not_replace_existing_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            source, destination = root / 'source', root / 'saved'
            source.mkdir(); destination.mkdir()
            manifest, _ = self.fixture(source)
            protected = destination / 'vless.txt'
            protected.write_bytes(b'protected-previous-snapshot\n')
            (source / 'vmess.txt').write_bytes(b'bad-download\n')
            with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
                audit.snapshot.prepare(manifest, destination, source)
            self.assertEqual(protected.read_bytes(), b'protected-previous-snapshot\n')
            self.assertEqual(list(destination.iterdir()), [protected])


if __name__ == '__main__':
    unittest.main(verbosity=2)
