"""Optional Xray reference server; synthetic local UDP targets only."""
import base64,contextlib,json,os,pathlib,socket,subprocess,tempfile,threading,time,unittest
from urllib.parse import quote
import test_udp_sdk as sdk
import test_expanded as old
import test_core as core

class EchoUDP:
    def __init__(self):
        self.socket=socket.socket(type=socket.SOCK_DGRAM);self.socket.bind(('127.0.0.1',0));self.port=self.socket.getsockname()[1];self.socket.settimeout(.1);self.stop=threading.Event()
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while not self.stop.is_set():
            try:data,source=self.socket.recvfrom(65536);self.socket.sendto(data,source)
            except socket.timeout:pass
            except OSError:return
    def close(self):self.stop.set();self.socket.close();self.thread.join(2)

@unittest.skipUnless(os.environ.get('VPN_CORE_XRAY_REFERENCE'),'Set VPN_CORE_XRAY_REFERENCE for local reference interoperability')
class XrayUdpReferenceTests(unittest.TestCase):
    setUpClass=classmethod(sdk.UdpSdkTests.setUpClass.__func__)
    tearDownClass=classmethod(sdk.UdpSdkTests.tearDownClass.__func__)
    engine=sdk.UdpSdkTests.engine;association=sdk.UdpSdkTests.association;transfer=sdk.UdpSdkTests.transfer
    @contextlib.contextmanager
    def server(self,protocol,cipher='',transport='raw',vision=False):
        with tempfile.TemporaryDirectory(dir=self.directory) as td:
            td=pathlib.Path(td);port=core.free_port();credential=str(old.ID)
            if protocol=='vless':settings={'clients':[{'id':str(old.ID),'flow':'xtls-rprx-vision' if vision else ''}],'decryption':'none'}
            elif protocol=='vmess':settings={'clients':[{'id':str(old.ID)}]}
            elif protocol=='trojan':settings={'clients':[{'password':old.SECRET}]};credential=quote(old.SECRET,safe='')
            else:
                secret=base64.b64encode(bytes(range(16 if '-128-' in cipher else 32))).decode() if cipher.startswith('2022-') else old.SECRET
                settings={'method':cipher,'password':secret,'network':'tcp,udp'};credential=base64.urlsafe_b64encode((cipher+':'+secret).encode()).decode().rstrip('=')
            stream={'network':transport if transport!='raw' else 'tcp','security':'tls' if protocol!='ss' else 'none'}
            if protocol!='ss':stream['tlsSettings']={'certificates':[{'certificateFile':str(core.CoreTests.cert),'keyFile':str(core.CoreTests.key)}],'alpn':['h2','http/1.1']}
            options=''
            if transport=='ws':stream['wsSettings']={'path':'/test'};options='&path=%2Ftest'
            if transport=='grpc':stream['grpcSettings']={'serviceName':'test'};options='&serviceName=test'
            if transport=='xhttp':stream['xhttpSettings']={'path':'/test','mode':'auto'};options='&path=%2Ftest&mode=packet-up'
            if vision:options+='&flow=xtls-rprx-vision'
            config={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':protocol if protocol!='ss' else 'shadowsocks','settings':settings,'streamSettings':stream}],
                'outbounds':[{'protocol':'freedom'}]}
            file=td/'server.json';file.write_text(json.dumps(config));log=td/'server.log'
            with log.open('w') as output:
                p=subprocess.Popen([os.environ['VPN_CORE_XRAY_REFERENCE'],'run','-config',str(file)],stdout=output,stderr=subprocess.STDOUT)
                try:
                    end=time.monotonic()+5
                    while True:
                        if p.poll() is not None:raise AssertionError(log.read_text())
                        try:
                            with socket.create_connection(('127.0.0.1',port),.1):break
                        except OSError:
                            if time.monotonic()>end:raise AssertionError(log.read_text())
                            time.sleep(.02)
                    uri=f'{protocol}://{credential}@127.0.0.1:{port}?type={transport}&security={stream["security"]}&sni=localhost&fp=native{options}'
                    if protocol=='vmess':uri+='&encryption='+cipher
                    yield uri,log
                finally:p.terminate();p.wait(5)
    def test_udp_four_protocols_and_transports(self):
        echo=EchoUDP();target=b'\1\x7f\0\0\1'+echo.port.to_bytes(2,'big')
        cases=[('vless','',t,False) for t in ('raw','ws','grpc','xhttp')]
        cases+=[('vless','','raw',True),('trojan','','raw',False)]
        cases+=[('vmess',c,'raw',False) for c in ('aes-128-gcm','chacha20-poly1305','none','zero')]
        cases+=[('ss',c,'raw',False) for c in ('aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305')]
        try:
            for proto,cipher,transport,vision in cases:
                with self.subTest(protocol=proto,cipher=cipher,transport=transport,vision=vision),self.server(proto,cipher,transport,vision) as (uri,server_log):
                    with self.engine(uri) as (port,log):
                        try:self.transfer(port,(b'packet one',b'packet two\0\xff',os.urandom(1234)),target)
                        except BaseException as e:e.add_note(log.read_text()+server_log.read_text());raise
        finally:echo.close()
if __name__=='__main__':unittest.main(verbosity=2)
