"""Run the selected-core node runner through an independent HTTPS/VLESS peer."""
import hashlib,json,os,pathlib,select,socket,ssl,subprocess,sys,tempfile,unittest
import test_core as core
from test_batch import Service,ID

class NodeRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):core.CoreTests.setUpClass()
    @classmethod
    def tearDownClass(cls):core.CoreTests.tearDownClass()
    def test_original_identity_and_all_success_http_statuses(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key)
        def origin(s):
            with context.wrap_socket(s,server_side=True) as tls:
                request=b''
                while b'\r\n\r\n' not in request:request+=tls.recv(4096)
                status=int(request.split(b' ')[1].strip(b'/'))
                tls.sendall(f'HTTP/1.1 {status} Synthetic\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode())
                try:tls.unwrap().close()
                except (OSError,ssl.SSLError):pass
        target=Service(origin)
        def forward(s):
            header=core.exact(s,18);self.assertEqual(header,b'\0'+bytes.fromhex(ID.replace('-',''))+b'\0')
            self.assertEqual(core.exact(s,1),b'\1');port=int.from_bytes(core.exact(s,2),'big')
            kind=core.exact(s,1)
            if kind==b'\2':host=core.exact(s,core.exact(s,1)[0]).decode()
            elif kind==b'\1':host=socket.inet_ntoa(core.exact(s,4))
            else:raise ValueError('Unexpected destination')
            self.assertIn(host,('localhost','127.0.0.1'));self.assertEqual(port,target.port)
            with socket.create_connection(('127.0.0.1',port),2) as remote:
                s.sendall(b'\0\0')
                while True:
                    ready,_,_=select.select([s,remote],[],[],3)
                    if not ready:return
                    for source in ready:
                        data=source.recv(16384)
                        if not data:return
                        (remote if source is s else s).sendall(data)
        proxy=Service(forward)
        try:
            with tempfile.TemporaryDirectory() as td:
                td=pathlib.Path(td);nodes=td/'protocols';nodes.mkdir()
                uri=f'vless://{ID}@127.0.0.1:{proxy.port}?security=none&type=raw#original-label'
                path=nodes/'vless.txt';path.write_text(uri+'\n')
                manifest=td/'manifest.json';manifest.write_text(json.dumps({'commit':'synthetic-pre','files':[{'name':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}]}))
                env=dict(os.environ,CURL_CA_BUNDLE=str(core.CoreTests.cert))
                for status in [200,202,204,206]:
                    out=td/f'results-{status}'
                    result=subprocess.run([sys.executable,core.ROOT/'scripts/Test-Nodes.py','--core',core.BIN,'--nodes',nodes,'--pre-manifest',manifest,'--source-commit','synthetic-core','--shards','1','--output',out,'--url',f'https://localhost:{target.port}/{status}'],env=env,capture_output=True,text=True,timeout=20)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    row=json.loads((out/'results.ndjson').read_text());self.assertEqual(row['status'],'PASS',row);self.assertEqual(row['http_status'],status)
                    self.assertEqual(row['node_id'],hashlib.sha256(uri.encode()).hexdigest()[:20]);self.assertNotIn(ID,(out/'results.ndjson').read_text())
                    self.assertEqual(path.read_text(),uri+'\n')
            self.assertEqual(proxy.errors,[]);self.assertEqual(target.errors,[])
        finally:proxy.close();target.close()

    def test_https_credentials_are_rejected_before_network(self):
        result=subprocess.run([sys.executable,core.ROOT/'scripts/Test-Nodes.py','--core',core.BIN,'--nodes','unused','--pre-manifest','unused','--output','unused','--source-commit','synthetic','--url','https://user:secret@localhost/'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0);self.assertIn('without credentials',result.stderr)
