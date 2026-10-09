"""Native C ABI cancellation, FD ownership, and nonblocking packet dispatch."""
import ctypes,os,pathlib,socket,ssl,struct,sys,tempfile,threading,time,unittest
import test_core as core
import test_expanded as peers
from native_tun_peer import NativeTunPeer
sys.path.insert(0,str(core.ROOT/'sdk/native'))
from tun_host import TunHost,Options
BUILD=pathlib.Path(os.environ.get('VPN_NATIVE_BUILD',core.ROOT/'build/linux-amd64'))
def checksum(b):
    if len(b)%2:b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b))
    while s>>16:s=(s&65535)+(s>>16)
    return (~s)&65535
SRC=socket.inet_aton('198.18.0.2');DST=socket.inet_aton('203.0.113.9')
def packet(proto,payload=b'',seq=1000,ack=0,flags=2):
    segment=struct.pack('!HHIIBBHHH',32123,443,seq,ack,80,flags,65535,0,0) if proto==6 else struct.pack('!HHHH',32124,443,len(payload)+8,0)
    segment+=payload;check=checksum(SRC+DST+struct.pack('!BBH',0,proto,len(segment))+segment);offset=16 if proto==6 else 6
    segment=segment[:offset]+struct.pack('!H',check or (65535 if proto==17 else 0))+segment[offset+2:]
    header=struct.pack('!BBHHHBBH4s4s',69,0,20+len(segment),0,0,64,proto,0,SRC,DST)
    return header[:10]+struct.pack('!H',checksum(header))+header[12:]+segment
@unittest.skipIf(os.name=='nt','FD ownership/dispatch tested on POSIX; Windows uses Wintun device tests')
class NativeRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        core.CoreTests.setUpClass();cls.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);cls.context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key)
    @classmethod
    def tearDownClass(cls):core.CoreTests.tearDownClass()
    def host(self,cfg,fd,resolve):return TunHost(BUILD,cfg,fd=fd,protect=lambda _:True,resolve=resolve)
    def test_slow_bootstrap_does_not_block_packet_reader_or_other_flow(self):
        peer=NativeTunPeer('vless',tls_context=self.context);first=threading.Event();release=threading.Event();count=0;lock=threading.Lock()
        def resolver(host):
            nonlocal count
            with lock:count+=1;mine=count
            if mine==1:first.set();release.wait(5)
            return ['127.0.0.1']
        with tempfile.TemporaryDirectory() as td:
            cfg=pathlib.Path(td)/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@fixture.invalid:{peer.port}?security=tls&sni=localhost&fp=chrome\ntls_ca_file={core.CoreTests.ca}\nconnect_timeout_ms=2000\n')
            app,tun=socket.socketpair(type=socket.SOCK_DGRAM);app.settimeout(3);host=self.host(cfg,tun.fileno(),resolver)
            try:
                host.start();app.send(packet(6));syn=app.recv(65535);self.assertEqual(syn[9],6);server_seq=struct.unpack('!I',syn[24:28])[0]
                app.send(packet(6,seq=1001,ack=server_seq+1,flags=16));self.assertTrue(first.wait(2))
                payload=b'TUN reader and second flow remain live';start=time.monotonic();app.send(packet(17,payload))
                deadline=start+1.5
                while True:
                    reply=app.recv(65535)
                    if reply[9]==17:self.assertEqual(reply[28:],payload);break
                    if time.monotonic()>deadline:self.fail('Reader waited for unrelated blocked connection')
                self.assertLess(time.monotonic()-start,1.5)
                # Busy run must not reset global state or hooks.
                duplicate=self.host(cfg,tun.fileno(),resolver);self.assertEqual(duplicate.core.vpn_core_run_tun(duplicate.config,ctypes.byref(duplicate.options),duplicate.protect_callback,duplicate.resolve_callback,None),2)
            finally:
                release.set();self.assertEqual(host.stop(),0);self.assertGreaterEqual(tun.fileno(),0);os.fstat(tun.fileno());app.close();tun.close();peer.close()
    def test_bad_certificate_has_original_reason_and_preserves_tunnel(self):
        peer=NativeTunPeer('vless',tls_context=self.context)
        with tempfile.TemporaryDirectory() as td:
            cfg=pathlib.Path(td)/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&sni=wrong.invalid&fp=chrome\ntls_ca_file={core.CoreTests.ca}\n')
            app,tun=socket.socketpair(type=socket.SOCK_DGRAM);host=self.host(cfg,tun.fileno(),lambda _:['127.0.0.1'])
            try:
                host.start();app.send(packet(17,b'must-not-reach-peer'));deadline=time.monotonic()+5
                while not host.errors and time.monotonic()<deadline:host.drain();time.sleep(.01)
                self.assertTrue(host.errors);self.assertTrue(any('TLS' in e['reason_code'] or 'CERT' in e['reason_code'] for e in host.errors),host.errors)
                self.assertTrue(host.core.vpn_core_tun_ready());self.assertEqual(peer.accepted,0)
            finally:self.assertEqual(host.stop(),0);app.close();tun.close();peer.close()
    def test_repeated_cancel_joins_and_borrowed_fd_remains_open(self):
        with tempfile.TemporaryDirectory() as td:
            cfg=pathlib.Path(td)/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:9?security=tls&sni=localhost&fp=chrome\nconnect_timeout_ms=1000\n')
            def cycle():
                app,tun=socket.socketpair(type=socket.SOCK_DGRAM);host=self.host(cfg,tun.fileno(),lambda _:['127.0.0.1'])
                try:host.start();app.send(packet(17,b'x'));self.assertEqual(host.stop(),0);os.fstat(tun.fileno());self.assertEqual(host.core.vpn_core_tun_ready(),0)
                finally:app.close();tun.close()
            previous=None;stable=0
            for _ in range(24):
                cycle();n=len(os.listdir('/proc/self/fd'));stable=stable+1 if n==previous else 0;previous=n
                if stable>=4:break
            self.assertGreaterEqual(stable,4);baseline=previous
            for _ in range(32):cycle();self.assertLessEqual(len(os.listdir('/proc/self/fd')),baseline)
if __name__=='__main__':unittest.main()
