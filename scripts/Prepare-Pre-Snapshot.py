"""Fetch a commit-pinned Pre snapshot and verify its bytes before use."""
import argparse
import datetime
import hashlib
import json
import pathlib
import shutil
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
NAMES = {'vless.txt', 'vmess.txt', 'trojan.txt', 'shadowsocks.txt'}


def prepare_latest(destination, manifest_path, fetch=None):
    def request(url):
        headers = {'User-Agent': 'vpn-core-pre-inventory'}
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as response:
            return response.read(100000001)
    fetch = fetch or request
    repository = 'noorelmostafa11-pixel/VPN-Nodes-Pre'
    head = json.loads(fetch('https://api.github.com/repos/' + repository + '/commits/main'))
    commit = head['sha']
    if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('Invalid latest Pre commit')
    # Resolve main once; every file below comes from this exact commit.
    files = []
    with tempfile.TemporaryDirectory(prefix='latest-pre-') as td:
        source = pathlib.Path(td)
        for name in sorted(NAMES):
            data = fetch('https://raw.githubusercontent.com/' + repository + '/' + commit +
                         '/output/protocols/' + name)
            if len(data) > 100000000:
                raise ValueError('Pre file exceeds size limit')
            count = sum(bool(s.strip()) and not s.strip().startswith('#')
                        for s in data.decode('utf-8-sig').splitlines())
            files.append({'name': name, 'bytes': len(data), 'nodes': count,
                          'sha256': hashlib.sha256(data).hexdigest()})
            (source / name).write_bytes(data)
        if not sum(e['nodes'] for e in files):
            raise ValueError('Latest Pre inventory is empty')
        manifest = {'repository': repository, 'commit': commit, 'directory': 'output/protocols',
                    'commit_utc': head['commit']['committer']['date'],
                    'resolved_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'files': files}
        prepare(manifest, destination, source)
    manifest_path = pathlib.Path(manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


def load_manifest(path):
    manifest = json.loads(pathlib.Path(path).read_text(encoding='utf-8-sig'))
    if manifest['repository'] != 'noorelmostafa11-pixel/VPN-Nodes-Pre':
        raise ValueError('Unexpected Pre repository')
    commit = manifest['commit']
    if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('Pre snapshot must use a full commit SHA')
    files = manifest['files']
    if len(files) != 4 or {entry['name'] for entry in files} != NAMES:
        raise ValueError('Pre snapshot must contain exactly four protocol files')
    if manifest['directory'] != 'output/protocols':
        raise ValueError('Unexpected Pre source directory')
    return manifest


def verify(data, entry):
    if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('Pre snapshot integrity mismatch: ' + entry['name'])
    rows = sum(bool(s.strip()) and not s.strip().startswith('#')
               for s in data.decode('utf-8-sig').splitlines())
    if rows != entry['nodes']:
        raise ValueError('Pre snapshot row count mismatch: ' + entry['name'])


def prepare(manifest, destination, source=None):
    destination = pathlib.Path(destination).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.pre-stage-', dir=destination.parent) as td:
        stage = pathlib.Path(td)
        for entry in manifest['files']:
            existing = destination / entry['name']
            if source:
                data = (pathlib.Path(source) / entry['name']).read_bytes()
            elif existing.is_file() and hashlib.sha256(existing.read_bytes()).hexdigest() == entry['sha256']:
                data = existing.read_bytes()
            else:
                url = ('https://raw.githubusercontent.com/' + manifest['repository'] + '/' +
                       manifest['commit'] + '/' + manifest['directory'] + '/' + entry['name'])
                with urllib.request.urlopen(url, timeout=120) as response:
                    data = response.read(entry['bytes'] + 1)
            verify(data, entry)
            (stage / entry['name']).write_bytes(data)
        # Never replace a different snapshot in place: it may back a report.
        if destination.exists():
            for entry in manifest['files']:
                existing = destination / entry['name']
                if existing.is_file() and existing.read_bytes() != (stage / entry['name']).read_bytes():
                    raise ValueError('Destination contains another snapshot; choose a new directory')
        destination.mkdir(parents=True, exist_ok=True)
        for entry in manifest['files']:
            shutil.copyfile(stage / entry['name'], destination / entry['name'])
    return sum(entry['nodes'] for entry in manifest['files'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=pathlib.Path, default=ROOT / 'docs/pre-current-source-manifest.json')
    parser.add_argument('--destination', type=pathlib.Path, default=ROOT / 'nodes/pre-current/protocols')
    parser.add_argument('--from-directory', type=pathlib.Path)
    parser.add_argument('--latest', action='store_true', help='Resolve Pre main and fetch its four files')
    parser.add_argument('--manifest-out', type=pathlib.Path)
    args = parser.parse_args()
    if args.latest:
        if not args.manifest_out:
            parser.error('--latest requires --manifest-out')
        manifest = prepare_latest(args.destination, args.manifest_out)
        total = sum(e['nodes'] for e in manifest['files'])
    else:
        manifest = load_manifest(args.manifest)
        total = prepare(manifest, args.destination, args.from_directory)
    print(f'HASH_VERIFIED: {total} Pre rows at {manifest["commit"]}')
