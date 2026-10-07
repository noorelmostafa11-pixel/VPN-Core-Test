"""Actual PowerShell batch: eight carrier variants, four protocols, HTTPS hashes."""
import contextlib,hashlib,json,pathlib,socket,ssl,subprocess,tempfile,threading,unittest
from test_core import ROOT,BIN
from test_batch import Service,PW,BODY
from test_xhttp_modes import XHttpTests
from test_mkcp import KCPPeer
import test_expanded as old

@unittest.skipUnless(PW,'Set VPN_CORE_POWERSHELL')
class PreBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):XHttpTests.setUpClass()
    @classmethod
    def tearDownClass(cls):XHttpTests.tearDownClass()
    def test_eight_new_carriers_four_protocols_https(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(old.original.CoreTests.cert,old.original.CoreTests.key);context.set_alpn_protocols(['http/1.1'])
        barrier=threading.Barrier(8);lock=threading.Lock();active=0;maximum=0
        def origin(raw):
            nonlocal active,maximum
            with context.wrap_socket(raw,server_side=True) as sock:
                data=b''
                while b'\r\n\r\n' not in data:data+=sock.recv(8192)
                with lock:active+=1;maximum=max(active,maximum)
                try:
                    barrier.wait(15);sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(BODY)).encode()+b'\r\nConnection: close\r\n\r\n'+BODY)
                    try:sock.unwrap().close()
                    except (OSError,ssl.SSLError):pass
                finally:
                    with lock:active-=1
        target=Service(origin);helper=XHttpTests();crypto=[];lines=[]
        try:
            with contextlib.ExitStack() as stack:
                variants=[('vless','','packet-up',True,False,{'_h3':True}),('vmess','aes-128-gcm','stream-up',True,False,{'_h3':True}),('trojan','','stream-one',True,False,{'_h3':True}),('ss','chacha20-ietf-poly1305','packet-up',True,False,{'_h3':True}),('vless','','stream-one',True,True,{'_legacy':True}),('vmess','chacha20-poly1305','stream-up',True,True,{}),('trojan','','packet-up',True,False,{})]
                for variant in variants:
                    uri,peer,log=stack.enter_context(helper.peer(*variant));peer.forward_target=('127.0.0.1',target.port);crypto.append(peer);lines.append(uri+'&fp=chrome')
                peer=old.Peer('ss','aes-256-gcm',tls_context=helper.context);peer.forward_target=('127.0.0.1',target.port);crypto.append(peer);stack.callback(peer.close)
                kcp=KCPPeer(peer,'synthetic-batch-seed',loss=True);stack.callback(kcp.close)
                credential=__import__('base64').urlsafe_b64encode(('aes-256-gcm:'+old.SECRET).encode()).decode().rstrip('=')
                lines.append(f'ss://{credential}@127.0.0.1:{kcp.port}?type=kcp&security=tls&sni=localhost&fp=chrome&seed=synthetic-batch-seed&mtu=900&tti=20')
                with tempfile.TemporaryDirectory(dir=helper.directory) as directory:
                    directory=pathlib.Path(directory);nodes=directory/'nodes.txt';nodes.write_text('\n'.join(lines)+'\n');reports=directory/'reports'
                    result=subprocess.run([PW,'-NoProfile','-File',str(ROOT/'scripts/Test-Batch.ps1'),'-Nodes',str(nodes),'-Core',str(BIN),'-Curl','curl','-Concurrency','8','-TimeoutSeconds','30','-Url',f'https://127.0.0.1:{target.port}/','-ExpectedBodySha256',hashlib.sha256(BODY).hexdigest(),'-TestCaFile',str(helper.ca),'-OutputDirectory',str(reports)],capture_output=True,text=True,timeout=100)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr);rows=[json.loads(s) for s in (reports/'results.ndjson').read_text().splitlines()]
                    self.assertEqual([x['status'] for x in rows],['PASS']*8,rows);self.assertEqual(maximum,8);self.assertEqual({x['protocol'] for x in rows},{'ss','vless','vmess','trojan'});self.assertTrue(all(x['body_sha256']==hashlib.sha256(BODY).hexdigest() for x in rows));self.assertEqual(sum(x['negotiated_alpn']=='h3' for x in rows),4)
                    for file in reports.iterdir():
                        text=file.read_text(encoding='utf-8-sig')
                        for secret in (str(old.ID),old.SECRET,'synthetic-batch-seed','vless://','vmess://','ss://','trojan://'):self.assertNotIn(secret,text)
                    summary=json.loads((reports/'summary.json').read_text());summary['observed_max_concurrent_tunnels']=maximum
                    (ROOT/'docs/pre-expansion-batch-summary.json').write_text(json.dumps(summary,indent=2)+'\n');(ROOT/'docs/pre-expansion-batch-results.ndjson').write_text((reports/'results.ndjson').read_text());(ROOT/'docs/pre-expansion-batch-output.txt').write_text(result.stdout+result.stderr)
                self.assertEqual(target.errors+sum((p.errors for p in crypto),[])+kcp.errors,[])
        finally:target.close()
if __name__=='__main__':unittest.main(verbosity=2)
