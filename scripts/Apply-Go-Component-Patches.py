"""Verify and apply the pinned project TLS/QUIC component interfaces."""
import hashlib,json,pathlib
root=pathlib.Path(__file__).resolve().parents[1];patches=root/'components/patches'
for item in json.loads((patches/'manifest.json').read_text()):
 path=root/item['path'];digest=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
 if digest==item['patched_sha256']:continue
 if digest!=item['original_sha256']:raise SystemExit('Component source changed: '+item['path'])
 content=(patches/item['replacement']).read_bytes()
 if hashlib.sha256(content).hexdigest()!=item['patched_sha256']:raise SystemExit('Component patch checksum mismatch')
 path.write_bytes(content)
print('Pinned Go component patches verified.')
