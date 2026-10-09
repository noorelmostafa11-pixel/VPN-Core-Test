"""Isolated benchmark host; proxy and TUN load identical C++ ABI engines.
No alternate engine or packet forwarding subprocess is used inside this host.
"""
import argparse,ctypes as c,json,os,pathlib,signal,socket,sys,threading,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'sdk/native'))
from tun_host import TunHost,Protect,Resolve
p=argparse.ArgumentParser();p.add_argument('--build',required=True,type=pathlib.Path);p.add_argument('--config',required=True,type=pathlib.Path);p.add_argument('--mode',choices=['tun','proxy'],required=True);p.add_argument('--ready',required=True,type=pathlib.Path);a=p.parse_args();a.build=a.build.resolve()
if a.mode=='tun':
    host=TunHost(a.build,a.config,name='vpnbbench',wintun=a.build/'wintun.dll' if os.name=='nt' else None,protect=lambda _:True,resolve=lambda _:['127.0.0.1']);info=host.start()
    def stop(*_):host.request_stop()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    threading.Thread(target=lambda:(sys.stdin.readline(),stop()),daemon=True).start()
    a.ready.write_text(json.dumps({'mode':'tun','interface':'vpnbbench','pid':os.getpid(),'luid':info['luid']}))
    try:
        while host.thread.is_alive():host.drain();time.sleep(.02)
    finally:
        host.stop()
        a.ready.with_suffix('.metrics.json').write_text(json.dumps([e for e in host.events if e.get('event')=='tun_metrics'][-1:]))
else:
    # Same managed host, same callbacks/thread count, baseline packet-free entry.
    if os.name=='nt':directory=os.add_dll_directory(str(a.build));provider=c.CDLL(str(a.build/'vpn-tls.dll'));core=c.CDLL(str(a.build/'vpn-core.dll'))
    else:provider=c.CDLL(str(a.build/'libvpn-tls.so'));core=c.CDLL(str(a.build/'libvpn-core.so'))
    @Protect
    def protect(fd,user):return 1
    @Resolve
    def resolve(host,out,cap,user):data=b'127.0.0.1\n';c.memmove(out,data,len(data));return len(data)
    core.vpn_core_run_config.argtypes=[c.c_char_p,Protect,Resolve,c.c_void_p];result=[]
    thread=threading.Thread(target=lambda:result.append(core.vpn_core_run_config(os.fsencode(a.config.resolve()),protect,resolve,None)));thread.start()
    def stop(*_):core.vpn_core_stop()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    threading.Thread(target=lambda:(sys.stdin.readline(),stop()),daemon=True).start()
    deadline=time.monotonic()+10
    while not core.vpn_core_get_listen_port():
        if not thread.is_alive() or time.monotonic()>deadline:stop();thread.join();raise RuntimeError('Benchmark proxy startup failed')
        time.sleep(.01)
    a.ready.write_text(json.dumps({'mode':'proxy','port':core.vpn_core_get_listen_port(),'pid':os.getpid()}))
    try:
        while thread.is_alive():time.sleep(.02)
    finally:stop();thread.join()
