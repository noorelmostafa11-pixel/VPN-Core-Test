"""XHTTP against an independent Go HTTP server and Python crypto peers."""
import concurrent.futures
import contextlib
import hashlib
import json
import pathlib
import random
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.parse import quote
import test_expanded as old
from test_core import exact,ROOT

class XHttpTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__)
    tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core
    socks=old.ExpandedTests.socks
    @contextlib.contextmanager
    def peer(self,protocol,cipher,mode,tls=False,h2=False,extra=None,bad=''):
        crypto=old.Peer(protocol,cipher)
        options={'xPaddingBytes':'100-100','scMinPostsIntervalMs':1,**(extra or {})}
        separate=options.pop('_separate',False);fm=options.pop('_fm',None);h3=options.pop('_h3',False);legacy=options.pop('_legacy',False);target=options.pop('_target',f'127.0.0.1:{crypto.port}');ech=options.pop('_ech',False)
        sp=options.get('sessionIDPlacement',options.get('sessionPlacement','path')) or 'path'
        qp=options.get('seqPlacement','path') or 'path'
        placement=options.get('uplinkDataPlacement','body')
        if placement in ('','auto'):placement='body'
        tables={'Base62':'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz','hex':'0123456789abcdef'}
        table=tables.get(options.get('sessionIDTable',''),options.get('sessionIDTable',''))
        fixture=dict(Target=target,Cert=str(old.original.CoreTests.cert),Key=str(old.original.CoreTests.key),Path='/test',Mode=mode,
            ECH=ech,TLS=tls,H2=h2,H3=h3,Legacy=legacy,Split=separate,Method='PUT' if legacy else options.get('uplinkHTTPMethod','POST').upper(),SessionPlacement=sp,SeqPlacement=qp,
            SessionKey=options.get('sessionIDKey',options.get('sessionKey','X-Session' if sp=='header' else 'x_session')),
            SeqKey=options.get('seqKey','X-Seq' if qp=='header' else 'x_seq'),DataPlacement=placement,
            DataKey=options.get('uplinkDataKey','X-Data' if placement=='header' else 'x_data'),
            PaddingPlacement=options.get('xPaddingPlacement','queryInHeader'),PaddingHeader=options.get('xPaddingHeader','X-Padding'),PaddingKey=options.get('xPaddingKey','x_padding'),
            PaddingMin=90,PaddingMax=135,Obfs=options.get('xPaddingObfsMode',False),NoGRPC=legacy or options.get('noGRPCHeader',False),
            Table=table,SessionLength=options.get('sessionIDLength',0),Bad=bad)
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            directory=pathlib.Path(directory);cfg=directory/'server.json';cfg.write_text(json.dumps(fixture));log=(directory/'peer.log').open('w')
            process=subprocess.Popen([str(ROOT/'bin/xhttp-peer'),'-config',str(cfg)],stdout=subprocess.PIPE,stderr=log,text=True)
            try:
                endpoint=process.stdout.readline().strip();port=endpoint.rsplit(':',1)[1]
                if separate:
                    down_port=int(process.stdout.readline().strip().rsplit(':',1)[1])
                    options['downloadSettings']={'address':'127.0.0.1','port':down_port,'security':'tls' if tls else 'none','network':'xhttp','tlsSettings':{'serverName':'localhost','fingerprint':'firefox','alpn':['h2' if h2 else 'http/1.1']},'xhttpSettings':{'path':'/test','extra':{'xPaddingBytes':100}}}
                credential=quote(old.SECRET,safe='') if protocol=='trojan' else str(old.ID)
                if protocol=='ss':import base64;credential=base64.urlsafe_b64encode((cipher+':'+old.SECRET).encode()).decode().rstrip('=')
                wire_mode=options.pop('_uri_mode',mode)
                uri=f'{protocol}://{credential}@127.0.0.1:{port}?security={"tls" if tls else "none"}&type=xhttp&path=%2Ftest&mode={wire_mode}&sni=localhost'
                if legacy:uri=uri.replace('type=xhttp','type=http')
                if h3:uri+='&alpn=h3'
                if ech:uri+='&ech='+quote(process.stdout.readline().strip(),safe='')
                if protocol=='vmess':uri+='&encryption='+cipher
                uri+='&extra='+quote(json.dumps(options),safe='')
                if fm:uri+='&fm='+quote(json.dumps(fm),safe='')
                yield uri,crypto,directory/'peer.log'
            finally:
                process.terminate();process.wait(5);log.close();process.stdout.close();crypto.close()
    def exchange(self,protocol='vless',cipher='',mode='packet-up',tls=False,h2=False,extra=None,fp='',connections=1):
        with self.peer(protocol,cipher,mode,tls,h2,extra) as (uri,crypto,peer_log):
            if fp:uri+='&fp='+fp
            with self.core(uri) as (port,core_log):
                def run(seed):
                    try:sock=self.socks(port)
                    except Exception as e:
                        time.sleep(.05);raise AssertionError(core_log.read_text()+peer_log.read_text()) from e
                    with sock as s:
                        self.assertEqual(exact(s,len(old.HELLO)),old.HELLO)
                        payload=random.Random(seed).randbytes(100019);s.sendall(payload)
                        self.assertEqual(hashlib.sha256(exact(s,len(payload))).digest(),hashlib.sha256(payload).digest())
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(run,range(connections)))
                self.assertNotIn('failed phase=',core_log.read_text())
            self.assertEqual(crypto.errors,[]);self.assertEqual(peer_log.read_text(),'')
    def test_01_modes_all_protocols_http1(self):
        for mode in ('stream-one','stream-up','packet-up'):
            for protocol,cipher in [('vless',''),('vmess','aes-128-gcm'),('trojan',''),('ss','chacha20-ietf-poly1305')]:
                with self.subTest(mode=mode,protocol=protocol):self.exchange(protocol,cipher,mode)
    def test_02_tls_http2_modes_profiles(self):
        for mode in ('stream-one','stream-up','packet-up'):
            for fp in ('chrome','firefox','native'):
                with self.subTest(mode=mode,fp=fp):self.exchange(mode=mode,tls=True,h2=True,fp=fp,connections=2)
    def test_03_tls_http1_modes(self):
        for mode in ('stream-one','stream-up','packet-up'):self.exchange(mode=mode,tls=True,fp='chrome')
    def test_04_packet_metadata_placements_and_payload(self):
        for sp,qp,data in [('query','header','header'),('header','query','body'),('cookie','cookie','cookie'),('path','path','body')]:
            extra={'sessionIDPlacement':sp,'seqPlacement':qp,'uplinkDataPlacement':data,'uplinkHTTPMethod':'GET' if data!='body' else 'PUT',
                   'sessionIDKey':'session_test','seqKey':'sequence_test','uplinkDataKey':'test_data','serverMaxHeaderBytes':16000,'uplinkChunkSize':200,
                   'sessionIDTable':'Base62','sessionIDLength':24,'scMaxEachPostBytes':5000}
            with self.subTest(sp=sp,qp=qp,data=data):self.exchange(extra=extra,tls=True,h2=True,connections=2)
    def test_05_padding_obfuscation_placements(self):
        for placement in ('query','header','cookie','queryInHeader'):
            extra={'xPaddingObfsMode':True,'xPaddingPlacement':placement,'xPaddingMethod':'tokenish','xPaddingKey':'pad_test','xPaddingHeader':'X-Test-Pad','noGRPCHeader':True}
            with self.subTest(placement=placement):self.exchange(mode='stream-up',extra=extra,tls=True,h2=True)
    def test_06_auto_and_legacy_session_aliases(self):
        self.exchange(extra={'_uri_mode':'auto','sessionPlacement':'header','sessionKey':'X-Legacy-Session'})
    def test_07_request_reuse_limits(self):
        self.exchange(extra={'xmux':{'maxConcurrency':'2-4','hMaxRequestTimes':2,'hMaxReusableSecs':600,'hKeepAlivePeriod':1},'scMaxEachPostBytes':3000},tls=True,h2=True,connections=2)
    def test_08_parallel_eight_nodes(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(lambda i:self.exchange(mode=('packet-up','stream-up','stream-one')[i%3],tls=True,h2=True,fp=('chrome','firefox','native')[i%3]),range(8)))
    def test_10_separate_download_tls(self):
        for mode in ('packet-up','stream-up'):
            for h2 in (False,True):
                with self.subTest(mode=mode,h2=h2):self.exchange(mode=mode,tls=True,h2=h2,extra={'_separate':True},connections=2)
    def test_11_finalmask_all_connections(self):
        fm={'tcp':[{'type':'fragment','settings':{'packets':'tlshello','length':'30-40','delay':'0','maxSplit':200}}]}
        self.exchange(mode='packet-up',tls=True,h2=True,extra={'_separate':True,'_fm':fm,'xmux':{'hMaxRequestTimes':2}},connections=2)
    def test_12_http3_modes_protocols_profiles(self):
        for mode in ('packet-up','stream-up','stream-one'):
            for fp in ('native','chrome','firefox'):
                for protocol,cipher in [('vless',''),('vmess','aes-128-gcm'),('trojan',''),('ss','chacha20-ietf-poly1305')]:
                    with self.subTest(mode=mode,fp=fp,protocol=protocol):self.exchange(protocol,cipher,mode,tls=True,extra={'_h3':True},fp=fp,connections=2)
    def test_13_legacy_http2(self):
        for protocol,cipher in [('vless',''),('vmess','aes-128-gcm'),('trojan',''),('ss','chacha20-ietf-poly1305')]:
            for fp in ('chrome','firefox','native'):
                with self.subTest(protocol=protocol,fp=fp):self.exchange(protocol,cipher,'stream-one',tls=True,h2=True,extra={'_legacy':True},fp=fp,connections=2)
    def test_16_legacy_http2_cleartext(self):
        for protocol,cipher in [('vless',''),('vmess','aes-128-gcm'),('trojan',''),('ss','chacha20-ietf-poly1305')]:
            with self.subTest(protocol=protocol):self.exchange(protocol,cipher,'stream-one',h2=True,extra={'_legacy':True},connections=2)
    def test_09_bad_status_and_content_encoding(self):
        for bad in ('status','encoding'):
            with self.peer('vless','','stream-one',bad=bad) as (uri,crypto,peer_log):
                with self.core(uri) as (port,log):
                    with socket.create_connection(('127.0.0.1',port),5) as s:
                        s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0')
                        s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb')
                        reply=exact(s,10)
                        if reply[1]==0:
                            try:self.assertEqual(s.recv(100),b'')
                            except ConnectionResetError:pass
                    time.sleep(.03);self.assertIn('XHTTP_HTTP_STATUS' if bad=='status' else 'HTTP_CONTENT_ENCODING',log.read_text())

    def test_14_ech_http2(self):
        for mode in ('packet-up','stream-up','stream-one'):
            for fp in ('chrome','firefox','native'):
                with self.subTest(mode=mode,fp=fp):self.exchange(mode=mode,tls=True,h2=True,fp=fp,extra={'_ech':True},connections=2)
    def test_15_http3_wrong_certificate(self):
        for fp in ('chrome','firefox','native'):
            with self.subTest(fp=fp),self.peer('vless','','stream-one',tls=True,extra={'_h3':True}) as (uri,crypto,peer_log):
                with self.core(uri.replace('sni=localhost','sni=wrong.example')+'&fp='+fp+'&allowInsecure=1') as (port,log):
                    with socket.create_connection(('127.0.0.1',port),5) as s:
                        s.settimeout(10);s.sendall(b'\5\1\0');self.assertEqual(exact(s,2),b'\5\0')
                        s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');self.assertNotEqual(exact(s,10)[1],0)
                    time.sleep(.05);self.assertIn("TLS_CERTIFICATE_NAME",log.read_text())
                self.assertEqual(crypto.accepted,0)

if __name__=='__main__':unittest.main(verbosity=2)
