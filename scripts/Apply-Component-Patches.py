"""Apply the reviewed TLS/QUIC component patches after go mod vendor."""
import hashlib,json,pathlib
root=pathlib.Path(__file__).resolve().parents[1]/'tls-provider'
for item in json.loads((root/'component-patches/manifest.json').read_text()):
 path=root/item['path'];digest=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
 if digest==item['patched_sha256']:continue
 if digest!=item['original_sha256']:raise SystemExit('Component source changed: '+item['path'])
 content=(root/'component-patches'/item['replacement']).read_bytes()
 if hashlib.sha256(content).hexdigest()!=item['patched_sha256']:raise SystemExit('Component patch checksum mismatch')
 path.write_bytes(content)
print('TLS/QUIC component interface patches verified.')
