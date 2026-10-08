"""Run the actual PowerShell batch scheduler against independent local peers."""
import hashlib
import json
import os
import pathlib
import select
import signal
import time
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import test_core as original
from test_core import exact, ROOT, BIN, free_port

PW = os.environ.get('VPN_CORE_POWERSHELL')
BODY = b'HTTPS batch body through independent VPN core\n'
ID = '12345678-1234-4567-9234-567812345678'

class Service:
    def __init__(self, handler):
        self.handler = handler
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1',0))
        self.socket.listen(32)
        self.socket.settimeout(.2)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.errors = []
        self.thread = threading.Thread(target=self.run,daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try: s,_ = self.socket.accept()
            except socket.timeout: continue
            except OSError: return
            threading.Thread(target=self.handle,args=(s,),daemon=True).start()

    def handle(self,s):
        try:
            s.settimeout(15)
            self.handler(s)
        except (OSError,EOFError,ssl.SSLError): pass
        except Exception as e: self.errors.append(repr(e))
        finally: s.close()

    def close(self):
        self.stop.set(); self.socket.close(); self.thread.join(2)

@unittest.skipUnless(PW, 'Set VPN_CORE_POWERSHELL to run real batch scheduler tests')
class BatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): original.CoreTests.setUpClass()
    @classmethod
    def tearDownClass(cls): original.CoreTests.tearDownClass()

    @unittest.skipUnless(os.name=='posix','POSIX SIGINT test; Windows Ctrl+C needs laptop verification')
    def test_cancellation_saves_partial_report(self):
        def wait_peer(sock):
            exact(sock,1)
            time.sleep(10)
        peer=Service(wait_peer)
        try:
            with tempfile.TemporaryDirectory(dir=original.CoreTests.directory) as temp:
                temp=pathlib.Path(temp); nodes=temp/'nodes.txt'; reports=temp/'cancelled'
                nodes.write_text(''.join(f'trojan://synthetic-password@127.0.0.1:{peer.port}?type=raw&security=tls&sni=localhost#cancel-{i}\n' for i in range(20)))
                log=temp/'batch.log'
                with log.open('w') as output:
                    process=subprocess.Popen([PW,'-NoProfile','-File',str(ROOT/'scripts/Test-Batch.ps1'),'-Nodes',str(nodes),'-Core',str(BIN),'-Curl','curl','-Concurrency','4','-TimeoutSeconds','30','-OutputDirectory',str(reports)],stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                    try:
                        deadline=time.monotonic()+10
                        while 'Inventory:' not in log.read_text():
                            if process.poll() is not None or time.monotonic()>deadline: self.fail(log.read_text())
                            time.sleep(.03)
                        time.sleep(.4)
                        cancelled_at=time.monotonic()
                        process.send_signal(signal.SIGINT)
                        process.wait(15)
                        cancellation_seconds=time.monotonic()-cancelled_at
                        self.assertLess(cancellation_seconds,8)
                        self.assertTrue((reports/'summary.json').exists(),log.read_text())
                        summary=json.loads((reports/'summary.json').read_text())
                        self.assertFalse(summary['completed'])
                        rows=[json.loads(x) for x in (reports/'results.ndjson').read_text().splitlines()]
                        self.assertEqual(len(rows),20)
                        self.assertTrue(any(x['status']=='CANCELLED' for x in rows))
                        (ROOT/'docs/cancellation-test.json').write_text(json.dumps({'status':'PASS','platform':'PowerShell 7.4.6 on Linux','cancellation_seconds':round(cancellation_seconds,3),'rows_saved':len(rows),'statuses':summary['statuses']},indent=2)+'\n')
                    finally:
                        try: os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError: pass
                        process.wait()
        finally: peer.close()

    def test_mixed_batch_and_redaction(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(original.CoreTests.cert,original.CoreTests.key)
        def origin(s):
            with context.wrap_socket(s,server_side=True) as tls:
                data=b''
                while b'\r\n\r\n' not in data: data+=tls.recv(8192)
                tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(BODY)).encode()+b'\r\nConnection: close\r\n\r\n'+BODY)
                try: tls.unwrap().close()
                except (ssl.SSLError,OSError): pass
        target=Service(origin)
        def vless(s):
            header=exact(s,18)
            if header != b'\0'+bytes.fromhex(ID.replace('-',''))+b'\0': return
            if exact(s,1)!=b'\1': raise ValueError('command')
            port=int.from_bytes(exact(s,2),'big')
            if exact(s,1)!=b'\1' or exact(s,4)!=b'\x7f\0\0\1' or port!=target.port: raise ValueError('destination')
            with socket.create_connection(('127.0.0.1',port),5) as remote:
                s.sendall(b'\0\0')
                while True:
                    reads,_,_=select.select([s,remote],[],[],10)
                    if not reads: return
                    for source in reads:
                        data=source.recv(16384)
                        if not data: return
                        (remote if source is s else s).sendall(data)
        proxy=Service(vless)
        try:
            with tempfile.TemporaryDirectory(dir=original.CoreTests.directory) as temp:
                temp=pathlib.Path(temp)
                nodes=temp/'nodes.txt'
                valid=f'vless://{ID}@127.0.0.1:{proxy.port}?security=none&type=raw'
                lines=[valid+f'#test-{i}' for i in range(6)] + [f'vless://{ID}@127.0.0.1:{free_port()}?security=none&type=raw',valid.replace(ID,'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),valid+'&fp=chrome',valid.replace('type=raw','type=domainsocket'),'invalid-link']
                nodes.write_text('\n'.join(lines)+'\n')
                reports=temp/'results'
                result=subprocess.run([PW,'-NoProfile','-File',str(ROOT/'scripts/Test-Batch.ps1'),'-Nodes',str(nodes),'-Core',str(BIN),'-Curl','curl','-Concurrency','8','-TimeoutSeconds','5','-Url',f'https://127.0.0.1:{target.port}/','-ExpectedBodySha256',hashlib.sha256(BODY).hexdigest(),'-TestCaFile',str(original.CoreTests.ca),'-OutputDirectory',str(reports)],capture_output=True,text=True,timeout=90)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                rows=[json.loads(x) for x in (reports/'results.ndjson').read_text().splitlines()]
                self.assertEqual(len(rows),11)
                counts={x:sum(r['status']==x for r in rows) for x in ('PASS','FAIL','UNSUPPORTED','PARSE_INVALID')}
                self.assertEqual(counts,{'PASS':7,'FAIL':2,'UNSUPPORTED':1,'PARSE_INVALID':1},rows)
                summary=json.loads((reports/'summary.json').read_text())
                self.assertTrue(summary['completed'])
                for file in reports.iterdir():
                    text=file.read_text(encoding='utf-8-sig')
                    self.assertNotIn(ID,text)
                    self.assertNotIn('vless://',text)
                (ROOT/'docs/synthetic-batch-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
                (ROOT/'docs/synthetic-batch-output.txt').write_text(result.stdout+result.stderr)
                (ROOT/'docs/synthetic-batch-results.ndjson').write_text((reports/'results.ndjson').read_text())
            self.assertEqual(target.errors+proxy.errors,[])
        finally: proxy.close();target.close()

if __name__=='__main__': unittest.main(verbosity=2)
