"""Native C ABI cancellation, FD ownership, and nonblocking packet dispatch."""
import ctypes,hashlib,json,os,pathlib,socket,ssl,struct,subprocess,sys,tempfile,threading,time,unittest
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
    def test_cancel_before_worker_enters_native_startup(self):
        with tempfile.TemporaryDirectory() as td:
            cfg=pathlib.Path(td)/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:9?security=tls&sni=localhost&fp=chrome\n')
            app,tun=socket.socketpair(type=socket.SOCK_DGRAM);host=self.host(cfg,tun.fileno(),lambda _:['127.0.0.1'])
            entered=threading.Event();release=threading.Event();run=host._run
            def delayed():entered.set();release.wait(2);run()
            host.thread=threading.Thread(target=delayed,name='delayed-native-start')
            timer=threading.Timer(.1,release.set)
            try:
                host.thread.start();self.assertTrue(entered.wait(1));timer.start()
                self.assertEqual(host.stop(timeout=3),0);self.assertFalse(host.thread.is_alive());os.fstat(tun.fileno())
                self.assertEqual(host.core.vpn_core_tun_ready(),0);self.assertEqual(host.core.vpn_core_pending_callbacks(),0)
            finally:
                release.set();timer.cancel()
                if host.thread.is_alive():host.stop()
                app.close();tun.close()
    def test_completed_host_stop_cannot_cancel_next_host(self):
        with tempfile.TemporaryDirectory() as td:
            cfg=pathlib.Path(td)/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:9?security=tls&sni=localhost&fp=chrome\n')
            first_app,first_tun=socket.socketpair(type=socket.SOCK_DGRAM);second_app,second_tun=socket.socketpair(type=socket.SOCK_DGRAM)
            first=self.host(cfg,first_tun.fileno(),lambda _:['127.0.0.1']);second=self.host(cfg,second_tun.fileno(),lambda _:['127.0.0.1'])
            try:
                first.start();self.assertEqual(first.stop(),0);second.start()
                self.assertEqual(first.stop(),0);first.request_stop();time.sleep(.08)
                self.assertTrue(second.thread.is_alive());self.assertEqual(second.core.vpn_core_tun_ready(),1)
            finally:
                second.stop();first.stop();first_app.close();first_tun.close();second_app.close();second_tun.close()
    def test_busy_managed_host_rejected_without_stopping_owner(self):
        with tempfile.TemporaryDirectory() as td:
            cfg=pathlib.Path(td)/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:9?security=tls&sni=localhost&fp=chrome\n')
            app,tun=socket.socketpair(type=socket.SOCK_DGRAM);host=self.host(cfg,tun.fileno(),lambda _:['127.0.0.1']);other=self.host(cfg,tun.fileno(),lambda _:['127.0.0.1'])
            try:
                host.start()
                with self.assertRaisesRegex(RuntimeError,'owns'):other.start()
                other.stop();other.request_stop();time.sleep(.08)
                self.assertTrue(host.thread.is_alive());self.assertEqual(host.core.vpn_core_tun_ready(),1)
            finally:host.stop();app.close();tun.close()
    def test_tls13_remote_half_close_drains_backpressured_upload_before_join(self):
        from native_tun_client import PacketTCPClient
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td);fixture=td/'half-close-peer';ready=td/'ready.json';result=td/'result.json'
            subprocess.run(['go','build','-o',str(fixture),str(core.ROOT/'tests/native_half_close_peer.go')],check=True,timeout=60)
            peer=subprocess.Popen([str(fixture),'--cert',str(core.CoreTests.cert),'--key',str(core.CoreTests.key),'--ready',str(ready),'--result',str(result)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            deadline=time.monotonic()+10
            while not ready.exists():
                self.assertIsNone(peer.poll());self.assertLess(time.monotonic(),deadline);time.sleep(.01)
            cfg=td/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:{json.loads(ready.read_text())["port"]}?security=tls&sni=localhost&fp=chrome\ntls_ca_file={core.CoreTests.ca}\n')
            app,tun=socket.socketpair(type=socket.SOCK_DGRAM)
            def protect(fd):
                with socket.socket(fileno=os.dup(fd)) as sock:sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,8192)
                return True
            host=TunHost(BUILD,cfg,fd=tun.fileno(),protect=protect,resolve=lambda _:['127.0.0.1']);client=None
            try:
                host.start();client=PacketTCPClient(app);self.assertEqual(core.exact(client,len(peers.HELLO)),peers.HELLO)
                self.assertEqual(client.recv(1),b'') # server authenticated close_notify
                payload=bytes(i%251 for i in range(1024*1024));client.sendall(payload);client.shutdown_write()
                peer.wait(20);self.assertEqual(peer.returncode,0,peer.stderr.read().decode())
                observed=json.loads(result.read_text());self.assertEqual(observed['status'],'PASS',json.dumps(observed));self.assertEqual(observed['tls_version'],772)
                self.assertEqual(observed['bytes'],len(payload));self.assertEqual(observed['sha256'],hashlib.sha256(payload).hexdigest())
                host.drain();self.assertFalse(host.errors,host.errors)
            finally:
                if client:client.close()
                host.stop();app.close();tun.close()
                if peer.poll() is None:peer.kill();peer.wait()
                peer.stdout.close();peer.stderr.close()
    def test_ipv6_fragmented_udp_preserves_full_maximum_record(self):
        peer=NativeTunPeer('vless',tls_context=self.context)
        source=socket.inet_pton(socket.AF_INET6,'fd71:5650::2');target=socket.inet_pton(socket.AF_INET6,'2001:db8::9')
        with tempfile.TemporaryDirectory() as td:
            cfg=pathlib.Path(td)/'node.ini';cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&sni=localhost&fp=chrome\ntls_ca_file={core.CoreTests.ca}\n')
            app,tun=socket.socketpair(type=socket.SOCK_DGRAM);app.settimeout(8);host=self.host(cfg,tun.fileno(),lambda _:['127.0.0.1'])
            try:
                host.start()
                for ident,size in enumerate((32768,65527),1):
                    payload=bytes(i%251 for i in range(size));udp=struct.pack('!HHHH',32124,443,size+8,0)+payload
                    check=checksum(source+target+struct.pack('!I3xB',len(udp),17)+udp);udp=udp[:6]+struct.pack('!H',check or 65535)+udp[8:]
                    for offset in range(0,len(udp),1232):
                        chunk=udp[offset:offset+1232];fragment=struct.pack('!BBHI',17,0,offset|(int(offset+len(chunk)<len(udp))),ident)+chunk
                        app.send(struct.pack('!IHBB16s16s',6<<28,len(fragment),44,64,source,target)+fragment)
                    chunks={};total=None
                    while total is None or sum(map(len,chunks.values()))<total:
                        try:reply=app.recv(65535)
                        except TimeoutError:
                            host.drain();self.fail(f'UDP size={size}, chunks={len(chunks)}, total={total}, peer accepted={peer.accepted}, peer errors={peer.errors}, core={list(host.events)[-3:]}')
                        self.assertEqual(reply[0]>>4,6);self.assertEqual(reply[8:24],target);self.assertEqual(reply[24:40],source)
                        self.assertEqual(reply[6],44);self.assertEqual(reply[40],17)
                        bits=struct.unpack('!H',reply[42:44])[0];position=bits&0xfff8;data=reply[48:]
                        self.assertNotIn(position,chunks);chunks[position]=data
                        if not bits&1:total=position+len(data)
                    record=b''.join(chunks[k] for k in sorted(chunks));self.assertEqual(len(record),size+8)
                    self.assertEqual(struct.unpack('!HHH',record[:6]),(443,32124,size+8));self.assertEqual(record[8:],payload)
                    self.assertEqual(checksum(target+source+struct.pack('!I3xB',len(record),17)+record),0)
                self.assertFalse(host.errors);self.assertFalse(peer.errors)
            finally:self.assertEqual(host.stop(),0);app.close();tun.close();peer.close()
if __name__=='__main__':unittest.main()
