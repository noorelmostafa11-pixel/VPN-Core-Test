"""Measure the actual packet/flow ABI, excluding protocol and OS adapter costs.

Four exported calls per verified UDP exchange: inject/read/write/packet.
Reused foreign buffers keep controller allocation outside the measured Go heap.
Timing includes Python/ctypes and gVisor work, not pure language-call overhead.
Run each build in a separate process to avoid loading multiple Go runtimes.
"""
import argparse,ctypes as c,json,pathlib,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'))
from test_netstack_abi import PacketABI,packet,udp6

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--iterations',type=int,default=10000);a=p.parse_args()
    if a.iterations<1:p.error('iterations must be positive')
    rows=[]
    for family in (4,6):
        for size in (64,512,1200):
            payload=bytes(i%251 for i in range(size));incoming=packet(17,payload) if family==4 else udp6(payload)
            source=c.create_string_buffer(incoming);plain=c.create_string_buffer(payload);read=c.create_string_buffer(65535);out=c.create_string_buffer(65535)
            with PacketABI(a.build.resolve()) as api:
                api.inject(incoming);flow=api.accept();assert api.lib.vpn_tun_read(api.id,flow.id,read,len(read))==size
                def exchange():
                    assert api.lib.vpn_tun_inject(api.id,source,len(incoming))==len(incoming)
                    assert api.lib.vpn_tun_read(api.id,flow.id,read,len(read))==size
                    assert api.lib.vpn_tun_write(api.id,flow.id,plain,size)==size
                    n=api.lib.vpn_tun_packet(api.id,out,len(out))
                    assert n==(28 if family==4 else 48)+size
                    assert read.raw[:size]==payload and out.raw[n-size:n]==payload
                for _ in range(1000):exchange()
                before=api.metrics();start=time.perf_counter_ns();cpu=time.process_time_ns()
                for _ in range(a.iterations):exchange()
                cpu=time.process_time_ns()-cpu;duration=time.perf_counter_ns()-start;after=api.metrics()
                rows.append({'ip':family,'payload_bytes':size,'iterations':a.iterations,'exported_calls':a.iterations*4,'ns_per_exchange':duration/a.iterations,'cpu_ns_per_exchange':cpu/a.iterations,'go_alloc_bytes_per_exchange':(after['go_total_alloc_bytes']-before['go_total_alloc_bytes'])/a.iterations,'go_gc_cycles':after['go_gc_count']-before['go_gc_count'],'status':'PASS'})
    report={'schema':'vpn-netstack-abi-performance-v1','scope':__doc__,'build_provenance':json.loads((a.build/'build-provenance.json').read_text()),'measurements':rows,'status':'PASS'}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(rows),flush=True)
if __name__=='__main__':main()
