"""Reachable independent peers, blocked bootstrap callbacks and bounded shutdown."""
import contextlib,ctypes,json,os,pathlib,socket,tempfile,threading,time,unittest
import test_core as core
import test_expanded as peerlib
import test_udp_sdk as udp

PROTECT=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_int64,ctypes.c_void_p)
RESOLVE=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p)

class DrainedPeer(peerlib.Peer):
    """Count resources only after the independent peer's handlers have exited."""
    def __init__(self,*args,**kwargs):
        self.handlers=[]
        super().__init__(*args,**kwargs)
    def accept(self):
        while not self.stop.is_set():
            try:sock,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:return
            worker=threading.Thread(target=self.handle,args=(sock,),daemon=True)
            self.handlers.append(worker);worker.start()
    def drain(self):
        # The tests close their client before draining. Do not force-close a
        # handler that could still be using the socket or protocol state.
        for worker in self.handlers:
            worker.join(3)
            if worker.is_alive():raise AssertionError('Independent peer handler did not retire')
        self.handlers.clear()
    def close(self):
        super().close();self.drain()

class LifecycleAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        core.CoreTests.setUpClass();cls.directory=core.CoreTests.directory
        cls.lib=ctypes.CDLL(str(core.BIN.parent/('vpn-core.dll' if os.name=='nt' else 'libvpn-core.so')))
        cls.lib.vpn_core_run_config.argtypes=[ctypes.c_char_p,PROTECT,RESOLVE,ctypes.c_void_p]
        cls.lib.vpn_core_read_event.argtypes=[ctypes.c_void_p,ctypes.c_uint32]
        if os.name=='nt':cls.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    @classmethod
    def tearDownClass(cls):core.CoreTests.tearDownClass()
    def wait(self,condition,seconds=3):
        end=time.monotonic()+seconds
        while not condition():
            if time.monotonic()>=end:self.fail('Condition deadline exceeded')
            time.sleep(.005)
    def events(self):
        out=[];buffer=ctypes.create_string_buffer(4096)
        while self.lib.vpn_core_read_event(buffer,len(buffer))>0:out.append(json.loads(buffer.value))
        return out
    @contextlib.contextmanager
    def engine(self,uri,resolve,protect=None,extra=''):
        protect=protect or PROTECT(lambda fd,user:1)
        with tempfile.TemporaryDirectory() as td:
            path=pathlib.Path(td)/'node.ini';path.write_text(f'node_uri={uri}\nlisten_port=0\nconnect_timeout_ms=1000\n{extra}')
            result=[];worker=threading.Thread(target=lambda:result.append(self.lib.vpn_core_run_config(os.fsencode(path),protect,resolve,None)))
            worker.start()
            try:
                self.wait(lambda:self.lib.vpn_core_get_state()==2 or not worker.is_alive())
                self.assertEqual(self.lib.vpn_core_get_state(),2)
                yield self.lib.vpn_core_get_listen_port(),worker,result
            finally:
                self.lib.vpn_core_stop();worker.join(5)
                self.assertFalse(worker.is_alive(),'Run still draining: test must release callbacks before context exit')
                self.assertEqual(result,[0]);self.assertEqual(self.lib.vpn_core_pending_callbacks(),0)
    def request(self,port):
        s=socket.create_connection(('127.0.0.1',port),2);s.settimeout(2)
        s.sendall(b'\5\1\0');self.assertEqual(core.exact(s,2),b'\5\0');s.sendall(b'\5\1\0\1\x7f\0\0\1\0\x50');return s
    def answer(self,out,cap):
        text=b'127.0.0.1\n';ctypes.memmove(out,text,len(text));return len(text)
    def resource_handles(self):
        if os.name!='nt':return len(list(pathlib.Path('/proc/self/fd').iterdir()))
        kernel=self.kernel;kernel.GetCurrentProcess.restype=ctypes.c_void_p
        kernel.GetProcessHandleCount.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)]
        count=ctypes.c_uint32()
        self.assertTrue(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(),ctypes.byref(count)))
        return count.value
    def resource_snapshot(self):
        if os.name!='nt':
            return {'handles':self.resource_handles(),'threads':len(list(pathlib.Path('/proc/self/task').iterdir()))}
        # A snapshot handle is closed before counting process handles, so the
        # measuring code does not contribute to the measured result.
        class ThreadEntry(ctypes.Structure):
            _fields_=[('size',ctypes.c_uint32),('usage',ctypes.c_uint32),('id',ctypes.c_uint32),
                ('owner',ctypes.c_uint32),('priority',ctypes.c_int32),('delta',ctypes.c_int32),('flags',ctypes.c_uint32)]
        kernel=self.kernel
        kernel.CreateToolhelp32Snapshot.argtypes=[ctypes.c_uint32,ctypes.c_uint32]
        kernel.CreateToolhelp32Snapshot.restype=ctypes.c_void_p
        kernel.Thread32First.argtypes=kernel.Thread32Next.argtypes=[ctypes.c_void_p,ctypes.POINTER(ThreadEntry)]
        kernel.CloseHandle.argtypes=[ctypes.c_void_p]
        handle=kernel.CreateToolhelp32Snapshot(4,0)
        self.assertNotEqual(handle,ctypes.c_void_p(-1).value,'Thread snapshot failed')
        count=0;entry=ThreadEntry();entry.size=ctypes.sizeof(entry)
        try:
            self.assertTrue(kernel.Thread32First(handle,ctypes.byref(entry)))
            while True:
                if entry.owner==os.getpid():count+=1
                entry.size=ctypes.sizeof(entry)
                if not kernel.Thread32Next(handle,ctypes.byref(entry)):
                    self.assertEqual(ctypes.get_last_error(),18,'Thread enumeration failed');break
        finally:self.assertTrue(kernel.CloseHandle(handle))
        return {'handles':self.resource_handles(),'threads':count}
    def check_resource_cycles(self,action):
        """Bounded warmup, then a fixed baseline that never advances on growth.

        Go's Windows extra-M pool retains events/timers for reuse (runtime
        os_windows.go semacreate/minit/dropm). A cold process's aggregate handle
        count is not a per-session ownership counter. Require a demonstrated
        plateau, then reject growth in both handles and threads over 12 cycles.
        """
        evidence={'warmup':[],'measured':[]};baseline=None
        try:
            for _ in range(8):
                action();time.sleep(.05);sample=self.resource_snapshot();evidence['warmup'].append(sample)
                recent=evidence['warmup'][-3:]
                if len(recent)==3 and all(item==sample for item in recent):baseline=sample;break
            self.assertIsNotNone(baseline,'Resources did not stabilize during bounded warmup: '+json.dumps(evidence))
            evidence['baseline']=baseline
            for _ in range(12):
                action();end=time.monotonic()+3;stable=0
                while stable<3:
                    sample=self.resource_snapshot()
                    stable=stable+1 if all(sample[key]<=baseline[key] for key in baseline) else 0
                    if time.monotonic()>=end:
                        evidence['measured'].append(sample)
                        self.fail('Resource growth after warmup: '+json.dumps(evidence))
                    time.sleep(.02)
                evidence['measured'].append(sample)
        finally:print('resource acceptance '+json.dumps(evidence,sort_keys=True),flush=True)
    def test_blocked_first_bootstrap_does_not_block_second_or_stop(self):
        for transport in ('raw',):
            with self.subTest(transport=transport):
                def cycle():
                    peer=DrainedPeer('vless',transport=transport);entered=threading.Event();release=threading.Event();counter=[];lock=threading.Lock()
                    @RESOLVE
                    def resolve(host,out,cap,user):
                        with lock:counter.append(host);first=len(counter)==1
                        if first:entered.set();release.wait(8)
                        return self.answer(out,cap)
                    uri=f'vless://{peerlib.ID}@bootstrap.invalid:{peer.port}?security=none&type={transport}&path=%2Ftest'
                    try:
                        with self.engine(uri,resolve) as (port,worker,result):
                            first=self.request(port)
                            try:
                                self.assertTrue(entered.wait(2))
                                with self.request(port) as second:
                                    self.assertEqual(core.exact(second,10)[1],0)
                                    self.assertEqual(core.exact(second,len(peerlib.HELLO)),peerlib.HELLO)
                                    second.sendall(b'independent second session');self.assertEqual(core.exact(second,26),b'independent second session')
                                    self.assertFalse(release.is_set());self.assertGreaterEqual(len(counter),2)
                                    # First wait times out while callback stays alive and owns its buffer.
                                    self.assertNotEqual(core.exact(first,10)[1],0)
                                    self.assertGreater(self.lib.vpn_core_pending_callbacks(),0)
                                    self.lib.vpn_core_stop();self.wait(lambda:self.lib.vpn_core_get_listen_port()==0)
                                    self.assertEqual(self.lib.vpn_core_get_state(),3);self.assertTrue(worker.is_alive());self.assertEqual(result,[])
                                    second.settimeout(1);self.assertEqual(second.recv(1),b'')
                                    with self.assertRaises(OSError):socket.create_connection(('127.0.0.1',port),.2)
                                    event=self.events();self.assertTrue(any(e.get('reason_code') in ('BOOTSTRAP_DNS_TIMEOUT','BOOTSTRAP_DNS_FAILED') for e in event))
                            finally:release.set();first.close()
                        self.assertEqual(peer.errors,[])
                    finally:release.set();peer.close()
                self.check_resource_cycles(cycle)
    def test_provider_bootstrap_callback_independence(self):
        import test_xhttp_modes as http
        entered=threading.Event();release=threading.Event();counter=[];lock=threading.Lock()
        @RESOLVE
        def resolve(host,out,cap,user):
            with lock:counter.append(host);first=len(counter)==1
            if first:entered.set();release.wait(8)
            return self.answer(out,cap)
        with http.XHttpTests.peer(self,'vless','','stream-one',h2=True,extra={'_legacy':True}) as (uri,crypto,log):
            uri=uri.replace('@127.0.0.1:', '@bootstrap.invalid:')
            with self.engine(uri,resolve) as (port,worker,result):
                first=self.request(port)
                try:
                    self.assertTrue(entered.wait(2))
                    with self.request(port) as second:
                        self.assertEqual(core.exact(second,10)[1],0,log.read_text())
                        self.assertEqual(core.exact(second,len(peerlib.HELLO)),peerlib.HELLO)
                        second.sendall(b'provider second');self.assertEqual(core.exact(second,15),b'provider second')
                        self.assertGreaterEqual(len(counter),2);self.assertFalse(release.is_set())
                        self.lib.vpn_core_stop();self.wait(lambda:self.lib.vpn_core_get_listen_port()==0)
                        self.assertTrue(worker.is_alive());self.assertEqual(result,[])
                finally:release.set();first.close()

    def test_plain_vless_half_close_retires_connections(self):
        @RESOLVE
        def resolve(host,out,cap,user):return self.answer(out,cap)
        peer=DrainedPeer('vless')
        try:
            with self.engine(f'vless://{peerlib.ID}@bootstrap.invalid:{peer.port}?security=none&type=raw',resolve) as (port,worker,result):
                def cycle():
                    with self.request(port) as client:
                        self.assertEqual(core.exact(client,10)[1],0);self.assertEqual(core.exact(client,len(peerlib.HELLO)),peerlib.HELLO)
                        client.sendall(b'last payload');self.assertEqual(core.exact(client,12),b'last payload')
                        client.shutdown(socket.SHUT_WR);self.assertEqual(client.recv(1),b'')
                    peer.drain()
                self.check_resource_cycles(cycle)
                self.assertEqual(self.lib.vpn_core_pending_callbacks(),0)
            self.assertEqual(peer.errors,[])
        finally:peer.close()
    def test_resource_monitor_rejects_retained_sockets(self):
        sockets=[]
        try:
            def leak():
                sock=socket.socket();sock.bind(('127.0.0.1',0));sockets.append(sock)
            with self.assertRaisesRegex(AssertionError,'Resources did not stabilize'):
                self.check_resource_cycles(leak)
            self.assertEqual(len(sockets),8)
        finally:
            for sock in sockets:sock.close()
    def test_stop_cancels_socks_and_tls_wait_before_connect_deadline(self):
        @RESOLVE
        def resolve(host,out,cap,user):return self.answer(out,cap)
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(2)
        try:
            uri=f'vless://{peerlib.ID}@bootstrap.invalid:{listener.getsockname()[1]}?security=tls&sni=localhost'
            with self.engine(uri,resolve) as (port,worker,result):
                hanging=self.request(port);remote,_=listener.accept()
                silent=socket.create_connection(('127.0.0.1',port),1)
                try:
                    start=time.monotonic();self.lib.vpn_core_stop();worker.join(.8)
                    self.assertFalse(worker.is_alive());self.assertLess(time.monotonic()-start,.8)
                finally:hanging.close();silent.close();remote.close()
        finally:listener.close()
    def test_reachable_shadowsocks_udp_allow_then_deny_and_events(self):
        for deny in (False,True):
            peer=udp.ShadowsocksUdpPeer('aes-128-gcm');calls=[]
            @RESOLVE
            def resolve(host,out,cap,user):return self.answer(out,cap)
            @PROTECT
            def protect(fd,user):calls.append(fd);return 0 if deny else 1
            import base64
            credential=base64.urlsafe_b64encode(('aes-128-gcm:'+peer.password).encode()).decode()
            try:
                with self.engine(f'ss://{credential}@bootstrap.invalid:{peer.port}',resolve,protect) as (port,worker,result):
                    control,s,relay=udp.UdpSdkTests.association(self,port)
                    try:
                        packet=b'\0\0\0\1\x7f\0\0\1\0\x35actual UDP';s.sendto(packet,relay)
                        if deny:
                            s.settimeout(.2)
                            with self.assertRaises(socket.timeout):s.recvfrom(65536)
                            self.assertEqual(peer.received,[]);self.assertTrue(any(e.get('reason_code')=='SOCKET_PROTECTION_FAILED' for e in self.events()))
                        else:self.assertEqual(s.recvfrom(65536)[0],packet);self.assertEqual(len(peer.received),1)
                        self.assertTrue(calls)
                    finally:control.close();s.close()
            finally:peer.close()
    def test_udp_no_response_is_opt_in_and_not_unsupported(self):
        @RESOLVE
        def resolve(host,out,cap,user):return self.answer(out,cap)
        with socket.socket(type=socket.SOCK_DGRAM) as silent:
            silent.bind(('127.0.0.1',0))
            import base64
            credential=base64.urlsafe_b64encode(b'aes-128-gcm:synthetic-only-password').decode()
            with self.engine(f'ss://{credential}@bootstrap.invalid:{silent.getsockname()[1]}',resolve,extra='udp_response_timeout_ms=50\n') as (port,worker,result):
                control,s,relay=udp.UdpSdkTests.association(self,port)
                try:
                    s.sendto(b'\0\0\0\1\x7f\0\0\1\0\x35query',relay);time.sleep(.15)
                    events=self.events();self.assertTrue(any(e.get('reason_code')=='UDP_NO_RESPONSE' for e in events));self.assertFalse(any(e.get('reason_code')=='UNSUPPORTED' for e in events))
                finally:control.close();s.close()
    def test_reachable_tcp_and_provider_protection_rejection_sends_nothing(self):
        from test_batch import Service
        for transport in ('raw','http'):
            received=threading.Event();peer=Service(lambda sock:received.set())
            @RESOLVE
            def resolve(host,out,cap,user):return self.answer(out,cap)
            calls=[]
            @PROTECT
            def reject(fd,user):calls.append(fd);return 0
            try:
                # Establish reachability first; a closed port cannot prove protection.
                with socket.create_connection(('127.0.0.1',peer.port),1):pass
                self.assertTrue(received.wait(1));received.clear()
                uri=f'vless://{peerlib.ID}@bootstrap.invalid:{peer.port}?security=none&type={transport}&path=%2Ftest'
                with self.engine(uri,resolve,reject) as (port,worker,result):
                    with self.request(port) as client:self.assertNotEqual(core.exact(client,10)[1],0)
                    self.wait(lambda:any(e.get('reason_code')=='SOCKET_PROTECTION_FAILED' for e in self.events()))
                    self.assertGreater(len(calls),0);self.assertFalse(received.wait(.1))
                self.assertEqual(peer.errors,[])
            finally:peer.close()
    def test_callback_capacity_is_bounded_and_restart_drains(self):
        entered=[];lock=threading.Lock();release=threading.Event();peer=peerlib.Peer('vless')
        @RESOLVE
        def resolve(host,out,cap,user):
            with lock:entered.append(host)
            release.wait(8);return self.answer(out,cap)
        clients=[]
        try:
            with self.engine(f'vless://{peerlib.ID}@bootstrap.invalid:{peer.port}?security=none',resolve) as (port,worker,result):
                try:
                    clients=[self.request(port) for _ in range(16)];self.wait(lambda:len(entered)==16)
                    with self.request(port) as extra:self.assertNotEqual(core.exact(extra,10)[1],0)
                    self.assertEqual(len(entered),16);self.assertEqual(self.lib.vpn_core_pending_callbacks(),16)
                    self.wait(lambda:any(e.get('reason_code')=='DNS_CALLBACK_BUSY' for e in self.events()))
                    self.lib.vpn_core_stop();self.wait(lambda:self.lib.vpn_core_get_listen_port()==0);self.assertTrue(worker.is_alive())
                finally:release.set();[client.close() for client in clients]
        finally:release.set();peer.close()

    def test_event_buffer_query_does_not_consume_or_leak_uri(self):
        @RESOLVE
        def resolve(host,out,cap,user):return -1
        peer=peerlib.Peer('vless')
        try:
            with self.engine(f'vless://{peerlib.ID}@bootstrap.invalid:{peer.port}?security=none',resolve) as (port,worker,result):
                with self.request(port) as client:self.assertNotEqual(core.exact(client,10)[1],0)
                self.wait(lambda:self.lib.vpn_core_read_event(None,0)<0)
                required=-self.lib.vpn_core_read_event(None,0);buffer=ctypes.create_string_buffer(required)
                self.assertEqual(self.lib.vpn_core_read_event(buffer,required),required-1)
                event=json.loads(buffer.value);self.assertGreater(event['connection_id'],0);self.assertEqual(event['reason_code'],'BOOTSTRAP_DNS_FAILED')
                self.assertNotIn(str(peerlib.ID),buffer.value.decode());self.assertNotIn('bootstrap.invalid',buffer.value.decode())
        finally:peer.close()
