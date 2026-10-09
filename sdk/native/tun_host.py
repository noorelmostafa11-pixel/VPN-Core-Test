"""In-process Native TUN C ABI host. No packet forwarding subprocesses.

Embedding utility and integration tests; platform policy must be acquired by
an application before full-tunnel routes. Never treat device readiness as a
successful proxy connection. All borrowed fd/hook resources outlive join().
"""
import ctypes as c
import json, os, pathlib, socket, threading, time
from collections import deque

Protect=c.CFUNCTYPE(c.c_int,c.c_int64,c.c_void_p)
Resolve=c.CFUNCTYPE(c.c_int,c.c_char_p,c.c_void_p,c.c_int,c.c_void_p)
class Options(c.Structure):
    _fields_=[('size',c.c_uint32),('abi',c.c_uint32),('fd',c.c_int64),('kind',c.c_uint32),('mtu',c.c_uint32),('maximum_flows',c.c_uint32),('reserved',c.c_uint32),('interface_name',c.c_char_p),('wintun_path',c.c_char_p)]
class TunHost:
    def __init__(self,build,config,*,fd=-1,name='VpnCore-Test',wintun=None,protect=None,resolve=None,maximum_flows=64):
        self.build=pathlib.Path(build).resolve();self.config=os.fsencode(pathlib.Path(config).resolve())
        if os.name=='nt':
            self.dll_directory=os.add_dll_directory(str(self.build))
            self.provider=c.CDLL(str(self.build/'vpn-tls.dll'));self.core=c.CDLL(str(self.build/'vpn-core.dll'))
        else:self.provider=c.CDLL(str(self.build/'libvpn-tls.so'));self.core=c.CDLL(str(self.build/'libvpn-core.so'))
        self.core.vpn_core_run_tun.argtypes=[c.c_char_p,c.POINTER(Options),Protect,Resolve,c.c_void_p]
        self.core.vpn_core_read_event.argtypes=[c.c_void_p,c.c_uint32]
        if self.core.vpn_core_tun_abi_version()!=1:raise RuntimeError('Native TUN build required')
        self.name=name.encode();self.wintun=os.fsencode(pathlib.Path(wintun).resolve()) if wintun else None
        self.options=Options(c.sizeof(Options),1,fd,0 if fd>=0 else 2 if os.name=='nt' else 1,1500,maximum_flows,0,self.name,self.wintun)
        if not protect or not resolve:raise ValueError('Protected socket and underlying bootstrap resolver required')
        self.protected=0;self.errors=deque(maxlen=128);self.events=deque(maxlen=256);self.result=None
        def p(fd,user):
            try:
                ok=protect(fd)
                if ok:self.protected+=1
                return int(bool(ok))
            except Exception:return 0
        def r(host,out,capacity,user):
            try:
                addresses=resolve(host.decode());data=('\n'.join(addresses)+'\n').encode()
                if not addresses or len(data)>=capacity:return -1
                for ip in addresses:socket.inet_pton(socket.AF_INET6 if ':' in ip else socket.AF_INET,ip)
                c.memmove(out,data,len(data));return len(data)
            except Exception:return -1
        self.protect_callback=Protect(p);self.resolve_callback=Resolve(r)
        self.thread=threading.Thread(target=self._run,name='vpn-native-tun')
    def bootstrap_targets(self):
        self.core.vpn_core_bootstrap_targets.argtypes=[c.c_char_p,c.c_void_p,c.c_uint32]
        size=self.core.vpn_core_bootstrap_targets(self.config,None,0)
        if size>=-1 or size==-5:raise RuntimeError('Bootstrap metadata unavailable')
        data=c.create_string_buffer(-size)
        n=self.core.vpn_core_bootstrap_targets(self.config,data,len(data))
        if n<=0:raise RuntimeError('Invalid bootstrap metadata')
        return json.loads(data.raw[:n])
    def _run(self):self.result=self.core.vpn_core_run_tun(self.config,c.byref(self.options),self.protect_callback,self.resolve_callback,None)
    def drain(self):
        while True:
            data=c.create_string_buffer(8192);n=self.core.vpn_core_read_event(data,len(data))
            if n<=0:break
            event=json.loads(data.raw[:n]);self.events.append(event)
            if 'failure' in event.get('event',''):self.errors.append(event)
    def start(self,timeout=10):
        self.thread.start();deadline=time.monotonic()+timeout
        while not self.core.vpn_core_tun_ready():
            self.drain()
            if not self.thread.is_alive() or time.monotonic()>deadline:
                self.stop();raise RuntimeError('TUN startup failed: '+str(self.errors))
            time.sleep(.005)
        self.drain();return next(e for e in self.events if e.get('event')=='tun_ready')
    def request_stop(self):self.core.vpn_core_stop()
    def stop(self,timeout=10):
        deadline=time.monotonic()+timeout
        self.request_stop()
        # A worker can still be entering the blocking C ABI after the first
        # request. Repeat while joining so startup cannot consume cancellation.
        while self.thread.ident and self.thread.is_alive() and time.monotonic()<deadline:
            self.request_stop();self.thread.join(min(.02,max(0,deadline-time.monotonic())))
        if self.thread.is_alive():raise RuntimeError('Stop timed out; keep descriptor and hooks alive')
        self.drain()
        if self.core.vpn_core_pending_callbacks()!=0:raise RuntimeError('Undrained network hook leases')
        return self.result
