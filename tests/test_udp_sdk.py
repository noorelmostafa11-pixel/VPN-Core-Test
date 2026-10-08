"""Independent UDP wire peers, C ABI lifetime and fail-closed network hooks."""
import base64,contextlib,ctypes,hashlib,hmac,json,os,pathlib,socket,ssl,struct,subprocess,tempfile,threading,time,unittest
from urllib.parse import quote
from blake3 import blake3
from Crypto.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM,ChaCha20Poly1305
import test_core as core
import test_expanded as old
import test_support_additions as crypto_oracle

def address(sock):
    t=core.exact(sock,1)
    n=4 if t==b'\1' else 16 if t==b'\4' else None
    if t==b'\3':size=core.exact(sock,1);return t+size+core.exact(sock,size[0])+core.exact(sock,2)
    if n is None:raise ValueError('address type')
    return t+core.exact(sock,n+2)
def address_length(b):return 7 if b[0]==1 else 19 if b[0]==4 else 4+b[1]
def xchacha(key,nonce,data,decrypt=False):
    c=ChaCha20_Poly1305.new(key=key,nonce=nonce)
    if decrypt:return c.decrypt_and_verify(data[:-16],data[-16:])
    a,b=c.encrypt_and_digest(data);return a+b

class UdpStreamPeer(old.Peer):
    def handle(self,raw):
        sock=raw
        try:
            raw.settimeout(10);sock=self.tls_context.wrap_socket(raw,server_side=True) if self.tls_context else raw
            wire=old.Wrapped(sock,self.transport,path=self.path)
            if self.protocol=='vless':
                if core.exact(wire,18)!=b'\0'+old.ID.bytes+b'\0' or core.exact(wire,1)!=b'\2':raise ValueError('VLESS UDP header')
                port,t=core.exact(wire,2),core.exact(wire,1)
                if t==b'\2':host=core.exact(wire,core.exact(wire,1)[0])
                else:host=core.exact(wire,4 if t==b'\1' else 16)
                wire.sendall(b'\0\0')
                while True:
                    size=core.exact(wire,2);payload=core.exact(wire,int.from_bytes(size,'big'))
                    wire.sendall(size[:1]);wire.sendall(size[1:]+payload)
            elif self.protocol=='trojan':
                if core.exact(wire,56)!=hashlib.sha224(old.SECRET.encode()).hexdigest().encode() or core.exact(wire,3)!=b'\r\n\3':raise ValueError('Trojan UDP header')
                address(wire)
                if core.exact(wire,2)!=b'\r\n':raise ValueError('Trojan request delimiter')
                while True:
                    addr=address(wire);length=core.exact(wire,2)
                    if core.exact(wire,2)!=b'\r\n':raise ValueError('Trojan datagram delimiter')
                    payload=core.exact(wire,int.from_bytes(length,'big'));response=addr+length+b'\r\n'+payload
                    wire.sendall(response[:3]);wire.sendall(response[3:])
        except (EOFError,OSError,ssl.SSLError):pass
        except Exception as e:self.errors.append(repr(e))
        finally:sock.close()

class ShadowsocksUdpPeer:
    def __init__(self,method,identities=0):
        self.method=method;self.modern=method.startswith('2022-');self.size=16 if '-128-' in method else 24 if '-192-' in method else 32
        self.keys=[bytes([i+1])*self.size for i in range(identities+1)]
        self.password=':'.join(base64.b64encode(k).decode() for k in self.keys) if self.modern else old.SECRET
        self.master=self.keys[-1] if self.modern else crypto_oracle.master_key(self.size)
        self.socket=socket.socket(type=socket.SOCK_DGRAM);self.socket.bind(('127.0.0.1',0));self.socket.settimeout(.1)
        self.port=self.socket.getsockname()[1];self.stop=threading.Event();self.errors=[];self.received=[];self.replay=False;self.corrupt=False;self.server_session=os.urandom(8);self.count=0
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def subkey(self,salt):
        if self.modern:return blake3(self.master+salt,derive_key_context='shadowsocks 2022 session subkey').digest()[:self.size]
        prk=hmac.new(salt,self.master,'sha1').digest();a=hmac.new(prk,b'ss-subkey\1','sha1').digest();return (a+hmac.new(prk,a+b'ss-subkey\2','sha1').digest())[:self.size]
    def aead(self,key):return ChaCha20Poly1305(key) if 'chacha' in self.method else AESGCM(key)
    def run(self):
        while not self.stop.is_set():
            try:wire,source=self.socket.recvfrom(65536)
            except socket.timeout:continue
            except OSError:return
            try:
                if self.modern:
                    if 'chacha' in self.method:
                        plain=xchacha(self.master,wire[:24],wire[24:],True);header,body=plain[:16],plain[16:]
                    else:
                        dec=Cipher(algorithms.AES(self.keys[0]),modes.ECB()).decryptor();header=dec.update(wire[:16])+dec.finalize();offset=16
                        for i in range(len(self.keys)-1):
                            dec=Cipher(algorithms.AES(self.keys[i]),modes.ECB()).decryptor();identity=dec.update(wire[offset:offset+16])+dec.finalize();offset+=16
                            expected=bytes(a^b for a,b in zip(blake3(self.keys[i+1]).digest()[:16],header))
                            if identity!=expected:raise ValueError('SS2022 UDP identity')
                        body=self.aead(self.subkey(header[:8])).decrypt(header[4:],wire[offset:],None)
                    if body[0]!=0 or abs(time.time()-int.from_bytes(body[1:9],'big'))>30:raise ValueError('SS2022 UDP type/time')
                    body=body[11+int.from_bytes(body[9:11],'big'):];response=b'\1'+int(time.time()).to_bytes(8,'big')+header[:8]+b'\0\0'+body
                    separate=self.server_session+self.count.to_bytes(8,'big');self.count+=1
                    if 'chacha' in self.method:nonce=os.urandom(24);response=nonce+xchacha(self.master,nonce,separate+response)
                    else:
                        enc=Cipher(algorithms.AES(self.master),modes.ECB()).encryptor();response=enc.update(separate)+enc.finalize()+self.aead(self.subkey(self.server_session)).encrypt(separate[4:],response,None)
                elif self.method in ('none','plain'):body=wire;response=wire
                elif self.method.endswith(('-gcm','-poly1305')):
                    salt=wire[:self.size]
                    if self.method.startswith('xchacha'):body=xchacha(self.subkey(salt),bytes(24),wire[self.size:],True);salt=os.urandom(self.size);response=salt+xchacha(self.subkey(salt),bytes(24),body)
                    else:body=self.aead(self.subkey(salt)).decrypt(bytes(12),wire[self.size:],None);salt=os.urandom(self.size);response=salt+self.aead(self.subkey(salt)).encrypt(bytes(12),body,None)
                else:
                    size,niv=crypto_oracle.parameters(self.method);key=crypto_oracle.master_key(size)
                    if self.method.startswith('aes-'):
                        mode={'cfb':modes.CFB,'ctr':modes.CTR,'ofb':modes.OFB}[self.method.rsplit('-',1)[1]]
                        body=Cipher(algorithms.AES(key),mode(wire[:niv])).decryptor().update(wire[niv:]);iv=os.urandom(niv);response=iv+Cipher(algorithms.AES(key),mode(iv)).encryptor().update(body)
                    else:
                        body=crypto_oracle.oracle(self.method,key,wire[:niv],True)(wire[niv:]);iv=os.urandom(niv);response=iv+crypto_oracle.oracle(self.method,key,iv)(body)
                self.received.append(body)
                if self.corrupt:response=response[:-1]+bytes([response[-1]^1])
                self.socket.sendto(response,source)
                if self.replay:self.socket.sendto(response,source)
            except Exception as e:self.errors.append(repr(e))
    def close(self):self.stop.set();self.socket.close();self.thread.join(2)

class UdpSdkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        core.CoreTests.setUpClass();cls.directory=core.CoreTests.directory
        cls.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);cls.context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key);cls.context.set_alpn_protocols(['h2','http/1.1'])
    @classmethod
    def tearDownClass(cls):core.CoreTests.tearDownClass()
    @contextlib.contextmanager
    def engine(self,uri):
        with tempfile.TemporaryDirectory(dir=self.directory) as td:
            td=pathlib.Path(td);ready=td/'ready.json';cfg=td/'node.ini';log=td/'core.log'
            ca_key='test_ca_file' if 'test' in core.BIN.name else 'tls_ca_file'
            cfg.write_text(f'node_uri={uri}\nlisten_port=0\nready_file={ready}\nconnect_timeout_ms=2000\nidle_timeout_ms=10000\n{ca_key}={core.CoreTests.ca}\n')
            with log.open('w') as output:
                p=subprocess.Popen([str(core.BIN),'--config',str(cfg)],stdout=output,stderr=subprocess.STDOUT)
                try:
                    deadline=time.monotonic()+5
                    while not ready.exists():
                        if p.poll() is not None or time.monotonic()>deadline:raise AssertionError(log.read_text())
                        time.sleep(.01)
                    yield json.loads(ready.read_text())['port'],log
                finally:
                    p.terminate()
                    try:p.wait(5)
                    except subprocess.TimeoutExpired:p.kill();p.wait()
    def association(self,port):
        control=socket.create_connection(('127.0.0.1',port),3);control.settimeout(3)
        control.sendall(b'\5\1\0');self.assertEqual(core.exact(control,2),b'\5\0')
        control.sendall(b'\5\3\0\1'+bytes(6));reply=core.exact(control,10);self.assertEqual(reply[:4],b'\5\0\0\1')
        udp=socket.socket(type=socket.SOCK_DGRAM);udp.settimeout(4)
        return control,udp,('127.0.0.1',int.from_bytes(reply[-2:],'big'))
    def transfer(self,port,payloads=(b'DNS synthetic payload',b'\0\xffpacket two',b''),address=b'\3\x09localhost\0\x35'):
        control,udp,relay=self.association(port)
        try:
            for payload in payloads:
                request=b'\0\0\0'+address+payload;udp.sendto(request,relay);response,_=udp.recvfrom(65536);self.assertEqual(response,request)
        finally:control.close();udp.close()
    def test_vless_trojan_udp_transport_boundaries(self):
        for proto in ('vless','trojan'):
            for transport in ('raw','websocket','httpupgrade','grpc'):
                with self.subTest(protocol=proto,transport=transport):
                    peer=UdpStreamPeer(proto,transport=transport,tls_context=self.context,path='/test/Tun')
                    credential=str(old.ID) if proto=='vless' else quote(old.SECRET,safe='')
                    uri=f'{proto}://{credential}@127.0.0.1:{peer.port}?security=tls&type={transport}&sni=localhost&path=%2Ftest&serviceName=test&fp=native'
                    try:
                        with self.engine(uri) as (port,log):self.transfer(port)
                        self.assertEqual(peer.errors,[])
                    finally:peer.close()
    def test_shadowsocks_udp_cipher_matrix(self):
        methods=['none','aes-128-gcm','aes-192-gcm','aes-256-gcm','chacha20-ietf-poly1305','xchacha20-ietf-poly1305',
            'table','rc4','rc4-md5','salsa20','chacha20','chacha20-ietf','bf-cfb','cast5-cfb','idea-cfb','des-cfb','rc2-cfb','seed-cfb',
            'aes-128-cfb','aes-192-cfb','aes-256-cfb','aes-128-ctr','aes-256-ctr','aes-256-ofb','camellia-128-cfb','camellia-256-cfb',
            '2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305']
        for method in methods:
            with self.subTest(cipher=method):
                peer=ShadowsocksUdpPeer(method);credential=base64.urlsafe_b64encode((method+':'+peer.password).encode()).decode().rstrip('=')
                try:
                    with self.engine(f'ss://{credential}@127.0.0.1:{peer.port}') as (port,log):self.transfer(port)
                    self.assertEqual(peer.errors,[])
                finally:peer.close()
    def test_ss2022_identity_replay_and_corruption(self):
        peer=ShadowsocksUdpPeer('2022-blake3-aes-256-gcm',identities=2);peer.replay=True
        credential=base64.urlsafe_b64encode((peer.method+':'+peer.password).encode()).decode().rstrip('=')
        try:
            with self.engine(f'ss://{credential}@127.0.0.1:{peer.port}') as (port,log):
                control,udp,relay=self.association(port)
                try:
                    packet=b'\0\0\0\1\x7f\0\0\1\0\x35test'
                    udp.sendto(packet,relay);self.assertEqual(udp.recvfrom(1024)[0],packet)
                    udp.settimeout(.15)
                    with self.assertRaises(socket.timeout):udp.recvfrom(1024)
                    peer.corrupt=True;peer.replay=False;udp.sendto(packet,relay)
                    with self.assertRaises(socket.timeout):udp.recvfrom(1024)
                    self.assertIn('SS_UDP_REPLAY',log.read_text())
                finally:control.close();udp.close()
            self.assertEqual(peer.errors,[])
        finally:peer.close()
    def test_fragment_and_foreign_source_do_not_reach_proxy(self):
        peer=ShadowsocksUdpPeer('aes-128-gcm');credential=base64.urlsafe_b64encode(('aes-128-gcm:'+old.SECRET).encode()).decode()
        try:
            with self.engine(f'ss://{credential}@127.0.0.1:{peer.port}') as (port,log):
                control,udp,relay=self.association(port)
                try:
                    request=b'\0\0\0\1\x7f\0\0\1\0\x35hello';udp.sendto(request,relay);self.assertEqual(udp.recvfrom(1024)[0],request)
                    udp.sendto(b'\0\0\1'+request[3:],relay)
                    with socket.socket(type=socket.SOCK_DGRAM) as foreign:foreign.sendto(request,relay)
                    time.sleep(.15);self.assertEqual(len(peer.received),1)
                finally:control.close();udp.close()
        finally:peer.close()

class NetworkHookTests(unittest.TestCase):
    def test_ech_udp_tcp_dot_and_doh_resolver_sockets_are_protected(self):
        lib=ctypes.CDLL(str(core.BIN.parent/('vpn-core.dll' if os.name=='nt' else 'libvpn-core.so')))
        protect_type=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_int64,ctypes.c_void_p)
        resolve_type=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p)
        lib.vpn_core_run_config.argtypes=[ctypes.c_char_p,protect_type,resolve_type,ctypes.c_void_p]
        for scheme in ('udp','tcp','tls','https'):
            with self.subTest(resolver=scheme):
                peer=old.Peer('vless');calls=[]
                @protect_type
                def protect(fd,user):calls.append(fd);return 1 if len(calls)==1 else 0
                @resolve_type
                def resolve(host,out,cap,user):text=b'127.0.0.1\n';ctypes.memmove(out,text,len(text));return len(text)
                try:
                    with tempfile.TemporaryDirectory() as td:
                        path=pathlib.Path(td)/'node.ini';ech=quote('localhost+'+scheme+'://bootstrap.invalid:5353',safe='')
                        path.write_text(f'node_uri=vless://{old.ID}@bootstrap.invalid:{peer.port}?security=tls&sni=localhost&fp=native&ech={ech}\nlisten_port=0\nconnect_timeout_ms=2000\n')
                        result=[];worker=threading.Thread(target=lambda:result.append(lib.vpn_core_run_config(os.fsencode(path),protect,resolve,None)));worker.start()
                        try:
                            end=time.monotonic()+5
                            while lib.vpn_core_get_state()!=2 and worker.is_alive() and time.monotonic()<end:time.sleep(.01)
                            self.assertEqual(lib.vpn_core_get_state(),2)
                            with socket.create_connection(('127.0.0.1',lib.vpn_core_get_listen_port()),2) as client:
                                client.settimeout(4);client.sendall(b'\5\1\0');self.assertEqual(core.exact(client,2),b'\5\0')
                                client.sendall(b'\5\1\0\1\x7f\0\0\1\0\x50');self.assertNotEqual(core.exact(client,10)[1],0)
                            self.assertGreaterEqual(len(calls),2)
                        finally:lib.vpn_core_stop();worker.join(5)
                        self.assertFalse(worker.is_alive());self.assertEqual(result,[0])
                finally:peer.close()

    def test_provider_tcp_udp_http3_and_ech_are_protected(self):
        lib=ctypes.CDLL(str(core.BIN.parent/('vpn-core.dll' if os.name=='nt' else 'libvpn-core.so')))
        protect_type=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_int64,ctypes.c_void_p)
        resolve_type=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p)
        lib.vpn_core_run_config.argtypes=[ctypes.c_char_p,protect_type,resolve_type,ctypes.c_void_p]
        cases=[('xhttp','none','&mode=packet-up'),('http','none',''),('kcp','none',''),('quic','tls','&quicsecurity=none'),('xhttp','tls','&alpn=h3&mode=packet-up')]
        for transport,security,options in cases:
            with self.subTest(transport=transport,security=security):
                calls=[]
                @protect_type
                def protect(fd,user):calls.append(fd);return 0
                @resolve_type
                def resolve(host,out,cap,user):text=b'127.0.0.1\n';ctypes.memmove(out,text,len(text));return len(text)
                with tempfile.TemporaryDirectory() as td:
                    path=pathlib.Path(td)/'node.ini';path.write_text(f'node_uri=vless://{old.ID}@bootstrap.invalid:443?type={transport}&security={security}&sni=localhost&path=%2Ftest{options}\nlisten_port=0\nconnect_timeout_ms=1000\n')
                    result=[];worker=threading.Thread(target=lambda:result.append(lib.vpn_core_run_config(os.fsencode(path),protect,resolve,None)));worker.start()
                    try:
                        end=time.monotonic()+5
                        while lib.vpn_core_get_state()!=2 and worker.is_alive() and time.monotonic()<end:time.sleep(.01)
                        self.assertEqual(lib.vpn_core_get_state(),2)
                        with socket.create_connection(('127.0.0.1',lib.vpn_core_get_listen_port()),2) as client:
                            client.settimeout(3);client.sendall(b'\5\1\0');self.assertEqual(core.exact(client,2),b'\5\0')
                            client.sendall(b'\5\1\0\1\x7f\0\0\1\0\x50');self.assertNotEqual(core.exact(client,10)[1],0)
                        self.assertTrue(calls)
                    finally:lib.vpn_core_stop();worker.join(5)
                    self.assertFalse(worker.is_alive());self.assertEqual(result,[0])

    def test_c_abi_callbacks_reject_and_restart(self):
        name='vpn-core.dll' if os.name=='nt' else 'libvpn-core.so';lib=ctypes.CDLL(str(core.BIN.parent/name))
        protect_type=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_int64,ctypes.c_void_p)
        resolve_type=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p)
        lib.vpn_core_run_config.argtypes=[ctypes.c_char_p,protect_type,resolve_type,ctypes.c_void_p]
        self.assertEqual(lib.vpn_core_abi_version(),2)
        for deny in (False,True):
            peer=old.Peer('vless');calls=[];lookups=[]
            @protect_type
            def protect(fd,user):calls.append(fd);return 0 if deny else 1
            @resolve_type
            def resolve(host,out,cap,user):lookups.append(host);text=b'127.0.0.1\n';ctypes.memmove(out,text,len(text));return len(text)
            try:
                with tempfile.TemporaryDirectory() as td:
                    path=pathlib.Path(td)/'node.ini';path.write_text(f'node_uri=vless://{old.ID}@bootstrap.invalid:{peer.port}?security=none&type=raw\nlisten_port=0\nconnect_timeout_ms=1000\n')
                    results=[];worker=threading.Thread(target=lambda:results.append(lib.vpn_core_run_config(os.fsencode(path),protect,resolve,None)));worker.start()
                    try:
                        end=time.monotonic()+5
                        while lib.vpn_core_get_state()!=2 and worker.is_alive() and time.monotonic()<end:time.sleep(.01)
                        self.assertEqual(lib.vpn_core_get_state(),2);port=lib.vpn_core_get_listen_port();self.assertGreater(port,0)
                        self.assertEqual(lib.vpn_core_run_config(os.fsencode(path),protect,resolve,None),2)
                        s=socket.create_connection(('127.0.0.1',port),2);s.settimeout(3)
                        with s:
                            s.sendall(b'\5\1\0');self.assertEqual(core.exact(s,2),b'\5\0');s.sendall(b'\5\1\0\3\x0cexample.test\1\xbb');reply=core.exact(s,10)
                            self.assertEqual(reply[1],1 if deny else 0)
                            if not deny:self.assertEqual(core.exact(s,len(old.HELLO)),old.HELLO)
                        self.assertTrue(calls);self.assertEqual(lookups,[b'bootstrap.invalid']);self.assertEqual(peer.accepted,0 if deny else 1)
                    finally:lib.vpn_core_stop();worker.join(5)
                    self.assertFalse(worker.is_alive());self.assertEqual(results,[0]);self.assertEqual(lib.vpn_core_get_state(),0);self.assertEqual(lib.vpn_core_get_listen_port(),0)
            finally:peer.close()

if __name__=='__main__':unittest.main(verbosity=2)
