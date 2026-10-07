"""Inspect every pinned Pre row with the built core; do not connect to nodes."""
import argparse
import collections
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pre_snapshot', ROOT / 'scripts/Prepare-Pre-Snapshot.py')
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)

# Reports never include arbitrary option text, credentials, or complete URIs.
ENUMS = {
    'protocol': {'vless', 'vmess', 'trojan', 'ss'},
    'transport': {'raw', 'websocket', 'httpupgrade', 'grpc', 'xhttp', 'http', 'kcp'},
    'security': {'none', 'tls', 'reality', 'xtls'},
    'fingerprint': {'', 'unsafe', 'native', 'chrome', 'firefox', 'safari', 'ios', 'android',
                    'edge', '360', 'qq', 'random', 'randomized', 'randomizednoalpn'},
    'mode': {'', 'auto', 'gun', 'multi', '0', 'packet-up', 'stream-up', 'stream-one'},
    'flow': {'', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443', 'xtls-rprx-direct',
             'xtls-rprx-direct-udp443', 'xtls-rprx-origin', 'xtls-rprx-origin-udp443',
             'xtls-rprx-splice', 'xtls-rprx-splice-udp443'},
    'cipher': {'', 'auto', 'none', 'plain', 'zero', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
               'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
               'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb', 'chacha20-ietf-poly1305',
               'chacha20-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
               '2022-blake3-chacha20-poly1305'},
    'header_type': {'', 'none', 'None', 'http'},
    'plugin': {'none', 'v2ray-plugin'},
}


def audit(core, nodes, manifest, output):
    core = pathlib.Path(core).resolve()
    nodes, output = pathlib.Path(nodes), pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'summary.json').unlink(missing_ok=True)
    files, families, reasons, missing = [], collections.Counter(), collections.Counter(), collections.Counter()
    totals = collections.Counter()
    with (output / 'rows.ndjson').open('w', encoding='utf-8') as redacted:
        for entry in manifest['files']:
            source = nodes / entry['name']
            data = source.read_bytes()
            snapshot.verify(data, entry)
            original = {i: s.strip() for i, s in enumerate(data.decode('utf-8-sig').splitlines(), 1)
                        if s.strip() and not s.strip().startswith('#')}
            seen, counts = set(), collections.Counter()
            with tempfile.TemporaryFile(mode='w+b') as rows:
                subprocess.run([str(core), '--inspect-list', str(source.resolve())],
                               stdout=rows, stderr=subprocess.PIPE, timeout=120, check=True)
                rows.seek(0)
                for line in rows:
                    row = json.loads(line)
                    number = row['line']
                    if number in seen or number not in original:
                        raise ValueError('Inspection line coverage mismatch: ' + entry['name'])
                    seen.add(number)
                    node_id = hashlib.sha256(original[number].encode()).hexdigest()[:20]
                    if row['node_id'] != node_id:
                        raise ValueError('Inspection node identity mismatch: ' + entry['name'])
                    valid = row['config_valid']
                    absent = row.get('missing_features', [])
                    supported = valid and row['connectable_by_this_build'] and not absent
                    status = 'SUPPORTED' if supported else 'UNSUPPORTED' if valid else 'INVALID'
                    counts[status] += 1
                    reason = row.get('reason_code', '')
                    if reason:
                        reasons[reason] += 1
                    missing.update(absent)
                    clean = {key: row.get(key, '') if row.get(key, '') in values else 'INVALID'
                             for key, values in ENUMS.items()}
                    cipher = row.get('cipher', '')
                    if re.fullmatch(r'mlkem768x25519plus\.(native|xorpub|random)\.(0rtt|1rtt)', cipher):
                        clean['cipher'] = cipher
                    clean['vmess_authentication'] = 'legacy' if row.get('alter_id', 0) else 'aead'
                    clean['websocket_early_data'] = bool(row.get('websocket_early_data'))
                    clean['ech_configured'] = bool(row.get('ech_configured'))
                    clean['plugin_mux'] = bool(row.get('plugin_mux'))
                    alpn = row.get('alpn', [])
                    clean['alpn'] = [x if x in {'h3', 'h2', 'http/1.1'} else 'OTHER' for x in alpn]
                    if supported:
                        families[json.dumps(clean, sort_keys=True)] += 1
                    redacted.write(json.dumps({'source': entry['name'], 'line': number, 'node_id': node_id,
                                               'status': status, 'reason_code': reason,
                                               'missing_features': absent, **clean}) + '\n')
            if seen != set(original):
                raise ValueError('Incomplete inspection: ' + entry['name'])
            totals.update(counts)
            files.append({**entry, 'counts': dict(counts)})
    version = subprocess.check_output([str(core), '--version'], text=True, timeout=20).strip()
    expected = manifest.get('expected_support')
    coverage_met = not totals['UNSUPPORTED'] and (expected is None or
                    all(totals[key] == value for key, value in expected.items()))
    report = {'schema': 'vpn-pre-support-audit-v1', 'pre_repository': manifest['repository'],
              'pre_commit': manifest['commit'], 'core_version': version,
              'core_sha256': hashlib.sha256(core.read_bytes()).hexdigest(),
              'completed': True, 'coverage_met': coverage_met, 'network_test_performed': False, 'rows': sum(totals.values()),
              'counts': dict(totals), 'missing_features': dict(missing), 'invalid_reasons': dict(reasons),
              'files': files, 'families': [{'features': json.loads(k), 'rows': v}
                                        for k, v in sorted(families.items())]}
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ['pre_commit', 'rows', 'counts', 'missing_features',
                                                 'completed', 'coverage_met', 'network_test_performed']}))
    return 0 if coverage_met else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=pathlib.Path)
    parser.add_argument('--nodes', type=pathlib.Path, default=ROOT / 'nodes/pre-current/protocols')
    parser.add_argument('--manifest', type=pathlib.Path, default=ROOT / 'docs/pre-current-source-manifest.json')
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    raise SystemExit(audit(args.core, args.nodes, snapshot.load_manifest(args.manifest), args.output))
