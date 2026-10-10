"""Foreign-buffer ownership, backpressure and resource tests of the real ABI."""
import ctypes as c, json, os, pathlib, socket, struct, time, unittest
from test_native_tun_runtime import packet, checksum

BUILD=pathlib.Path(os.environ.get('VPN_NATIVE_BUILD',pathlib.Path(__file__).resolve().parents[1]/'build/linux-amd64'))
class Flow(c.Structure):
    _fields_=[('id',c.c_uint64),('protocol',c.c_uint32),('address_size',c.c_uint32),('address',c.c_uint8*16),('port',c.c_uint16),('reserved',c.c_uint16)]

class PacketABI:
    def __init__(self,build=BUILD,maximum=8):
        if os.name=='nt': self.directory=os.add_dll_directory(str(build.resolve()))
        self.lib=c.CDLL(str(build/('vpn-tls.dll' if os.name=='nt' else 'libvpn-tls.so')))
        for name,args,result in [('create',[c.c_int,c.c_int],c.c_uint64),('close',[c.c_uint64],None),('inject',[c.c_uint64,c.c_void_p,c.c_int],c.c_int),('packet',[c.c_uint64,c.c_void_p,c.c_int],c.c_int),('accept',[c.c_uint64,c.POINTER(Flow)],c.c_int),('read',[c.c_uint64,c.c_uint64,c.c_void_p,c.c_int],c.c_int),('write',[c.c_uint64,c.c_uint64,c.c_void_p,c.c_int],c.c_int),('shutdown_write',[c.c_uint64,c.c_uint64],c.c_int),('drop',[c.c_uint64,c.c_uint64],None),('metrics',[c.c_uint64,c.c_void_p,c.c_int],c.c_int),('resource_probe',[c.c_void_p,c.c_int],c.c_int)]:
            f=getattr(self.lib,'vpn_tun_'+name);f.argtypes=args;f.restype=result
        self.id=self.lib.vpn_tun_create(1500,maximum)
        if not self.id:raise RuntimeError('stack create failed')
    def inject(self,data):
        b=c.create_string_buffer(data);n=self.lib.vpn_tun_inject(self.id,b,len(data))
        c.memset(b,0,len(data)) # retained C input would corrupt the queued packet
        if n!=len(data):raise RuntimeError('packet input rejected')
    def accept(self):
        f=Flow();deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            n=self.lib.vpn_tun_accept(self.id,c.byref(f))
            if n==1:return f
            if n!=-2:raise RuntimeError('flow accept failed')
            time.sleep(.001)
        raise TimeoutError('flow not published')
    def output(self,capacity=65535):
        out=c.create_string_buffer(capacity);n=self.lib.vpn_tun_packet(self.id,out,capacity)
        return n,out.raw[:max(n,0)]
    def metrics(self):
        out=c.create_string_buffer(4096);n=self.lib.vpn_tun_metrics(self.id,out,len(out));return json.loads(out.raw[:n])
    def close(self):
        if self.id:self.lib.vpn_tun_close(self.id);self.id=0
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

def udp6(data):
    source=socket.inet_pton(socket.AF_INET6,'fd71:5650::2');target=socket.inet_pton(socket.AF_INET6,'2001:db8::9')
    udp=struct.pack('!HHHH',32124,443,len(data)+8,0)+data
    check=checksum(source+target+struct.pack('!I3xB',len(udp),17)+udp)
    udp=udp[:6]+struct.pack('!H',check or 65535)+udp[8:]
    return struct.pack('!IHBB16s16s',6<<28,len(udp),17,64,source,target)+udp

class PacketOwnershipTests(unittest.TestCase):
    def test_udp_borrowed_memory_retry_empty_records_and_checksums(self):
        for family in (4,6):
            for size in (0,1,512,1200):
                with self.subTest(ip=family,size=size),PacketABI() as api:
                    payload=bytes(i%251 for i in range(size));api.inject(packet(17,payload) if family==4 else udp6(payload));f=api.accept()
                    self.assertEqual(f.protocol,17);self.assertEqual(f.address_size,4 if family==4 else 16)
                    if size>1:
                        small=c.create_string_buffer(b'\xa5',1)
                        self.assertEqual(api.lib.vpn_tun_read(api.id,f.id,small,1),-3);self.assertEqual(small.raw,b'\xa5')
                    out=c.create_string_buffer(65535);n=api.lib.vpn_tun_read(api.id,f.id,out,len(out))
                    self.assertEqual(n,size);self.assertEqual(out.raw[:n],payload)
                    self.assertEqual(api.lib.vpn_tun_read(api.id,f.id,out,len(out)),-2)
                    source=c.create_string_buffer(payload)
                    self.assertEqual(api.lib.vpn_tun_write(api.id,f.id,source,size),size);c.memset(source,0xff,size)
                    tiny=c.create_string_buffer(b'\xcc',1)
                    self.assertEqual(api.lib.vpn_tun_packet(api.id,tiny,1),-3);self.assertEqual(tiny.raw,b'\xcc')
                    count,response=api.output();offset=20 if family==4 else 40
                    self.assertEqual(count,offset+8+size);self.assertEqual(response[offset+8:],payload)
                    self.assertEqual(struct.unpack('!HHH',response[offset:offset+6]),(443,32124,size+8))
                    pseudo=response[12:20]+struct.pack('!BBH',0,17,8+size) if family==4 else response[8:40]+struct.pack('!I3xB',8+size,17)
                    self.assertEqual(checksum(pseudo+response[offset:]),0);self.assertEqual(api.output()[0],-2)
    def test_tcp_queued_write_owns_bytes_and_send_shutdown_rejects(self):
        with PacketABI() as api:
            api.inject(packet(6));deadline=time.monotonic()+3
            while True:
                n,syn=api.output()
                if n>0:break
                self.assertLess(time.monotonic(),deadline);time.sleep(.001)
            server_seq=struct.unpack('!I',syn[24:28])[0];api.inject(packet(6,seq=1001,ack=server_seq+1,flags=16));f=api.accept()
            payload=bytes(i%251 for i in range(48000));source=c.create_string_buffer(payload)
            n=api.lib.vpn_tun_write(api.id,f.id,source,len(payload));self.assertGreater(n,0);c.memset(source,0xff,len(payload))
            parts={};deadline=time.monotonic()+3;first_seq=(server_seq+1)&0xffffffff
            while sum(map(len,parts.values()))<n:
                count,p=api.output()
                if count<=0:self.assertLess(time.monotonic(),deadline);time.sleep(.001);continue
                offset=20+(p[32]>>4)*4;seq=struct.unpack('!I',p[24:28])[0]
                if p[offset:]:
                    parts[(seq-first_seq)&0xffffffff]=p[offset:]
                    contiguous=0
                    for position in sorted(parts):
                        if position!=contiguous:break
                        contiguous+=len(parts[position])
                    api.inject(packet(6,seq=1001,ack=(first_seq+contiguous)&0xffffffff,flags=16))
            self.assertEqual(b''.join(parts[k] for k in sorted(parts)),payload[:n])
            self.assertEqual(api.lib.vpn_tun_shutdown_write(api.id,f.id),0)
            self.assertEqual(api.lib.vpn_tun_write(api.id,f.id,source,1),-1)
    def test_overload_reports_go_receive_drops_and_flow_rejections(self):
        with PacketABI(maximum=1) as api:
            api.inject(packet(17,b'a'));f=api.accept()
            for _ in range(1024):api.inject(packet(17,b'x'*1200))
            api.inject(udp6(b'different flow'))
            metrics=api.metrics();self.assertGreater(metrics['go_udp_receive_dropped_records'],0)
            self.assertGreater(metrics['go_rejected_flows'],0);self.assertEqual(metrics['active_flows'],1)
    def test_close_releases_pending_packet_and_registered_stack(self):
        for _ in range(32):
            api=PacketABI()
            try:
                api.inject(packet(17,b'pending'));f=api.accept();b=c.create_string_buffer(b'output')
                self.assertEqual(api.lib.vpn_tun_write(api.id,f.id,b,6),6);self.assertEqual(api.output(1)[0],-3)
            finally:api.close()
        out=c.create_string_buffer(4096);n=api.lib.vpn_tun_resource_probe(out,len(out))
        self.assertEqual(json.loads(out.raw[:n])['registered_stacks'],0)

if __name__=='__main__':unittest.main()
