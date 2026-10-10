"""Permitted local comparison without CAP_NET_ADMIN or external workflows.

Uses borrowed SOCK_DGRAM FD plus a bounded synthetic TCP application for TUN,
and OS sockets for proxy paths. The core/peer/app process boundaries, TLS peer,
payload and load are held constant. This is not Wintun/devTun/Android or WAN
throughput: synthetic-app scheduling may limit the TUN measurements.
"""
import argparse,importlib.util,json,os,pathlib,socket,ssl,statistics,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'))
import test_core as core
import test_expanded as peers
from native_tun_peer import NativeTunPeer
from native_tun_client import PacketTCPClient
spec=importlib.util.spec_from_file_location('existing_benchmark',ROOT/'scripts/Benchmark-Native-Tun.py');bench=importlib.util.module_from_spec(spec);spec.loader.exec_module(bench)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--stable',type=pathlib.Path,required=True);p.add_argument('--baseline',type=pathlib.Path,required=True);p.add_argument('--candidate',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--rounds',type=int,default=3);p.add_argument('--bytes',type=int,default=8*1024*1024);p.add_argument('--labels',nargs='+');p.add_argument('--transports',nargs='+',choices=['raw','websocket'],default=['raw','websocket']);a=p.parse_args()
    if sys.platform!='linux':p.error('This harness uses Linux borrowed FDs only; use the OS benchmark on Windows/Android')
    a.output.mkdir(parents=True,exist_ok=True);core.CoreTests.setUpClass();rows=[]
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(core.CoreTests.cert,core.CoreTests.key);context.set_alpn_protocols(['h2','http/1.1'])
    labels=[('stable-proxy',a.stable,'proxy'),('reviewed-proxy',a.baseline,'proxy'),('candidate-proxy',a.candidate,'proxy'),('reviewed-borrowed-tun',a.baseline,'tun'),('candidate-borrowed-tun',a.candidate,'tun')]
    if a.labels:
        if set(a.labels)-{row[0] for row in labels}:p.error('Unknown benchmark label')
        labels=[row for row in labels if row[0] in a.labels]
    try:
        for transport in a.transports:
            for repetition in range(a.rounds):
                peer=NativeTunPeer('vless',transport=transport,tls_context=context)
                try:
                    ordered=labels[repetition%len(labels):]+labels[:repetition%len(labels)]
                    for label,build,mode in ordered:
                        app,tun=socket.socketpair(type=socket.SOCK_DGRAM)
                        try:
                            with tempfile.TemporaryDirectory() as td:
                                td=pathlib.Path(td);ready=td/'ready.json';cfg=td/'node.ini';log=td/'host.log'
                                cfg.write_text(f'node_uri=vless://{peers.ID}@127.0.0.1:{peer.port}?security=tls&type={transport}&sni=localhost&path=/test&fp=chrome\ntls_ca_file={core.CoreTests.ca}\nlisten_port=0\nidle_timeout_ms=60000\nmax_connections=64\n')
                                args=[sys.executable,str(ROOT/'scripts/Native-Tun-Benchmark-Worker.py'),'--build',str(build.resolve()),'--config',str(cfg),'--mode',mode,'--ready',str(ready)]
                                if mode=='tun':args+=['--fd',str(tun.fileno())]
                                with log.open('w') as stream:
                                    process=subprocess.Popen(args,pass_fds=(tun.fileno(),) if mode=='tun' else (),stdin=subprocess.PIPE,text=True,stdout=stream,stderr=subprocess.STDOUT)
                                    try:
                                        deadline=time.monotonic()+15
                                        while not ready.exists():
                                            if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError(log.read_text()[-8192:])
                                            time.sleep(.01)
                                        info=json.loads(ready.read_text())
                                        def connect():
                                            if mode=='tun':return PacketTCPClient(app)
                                            s=socket.create_connection(('127.0.0.1',info['port']),10);s.sendall(b'\5\1\0');assert core.exact(s,2)==b'\5\0';s.sendall(b'\5\1\0\1'+socket.inet_aton('203.0.113.9')+b'\1\xbb');assert core.exact(s,10)[1]==0;return s
                                        bench.workload(connect,1024*1024)
                                        def sample(index):
                                            process.stdin.write(f'sample {index}\n');process.stdin.flush();path=ready.with_suffix(f'.sample-{index}.json');deadline=time.monotonic()+5
                                            while not path.exists():
                                                if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Local benchmark sample unavailable')
                                                time.sleep(.002)
                                            return json.loads(path.read_text())
                                        before=sample(1);result=bench.workload(connect,a.bytes);after=sample(2)
                                        result.update(label=label,transport=transport,repetition=repetition,cpu_seconds=after['cpu_seconds']-before['cpu_seconds'],rss_bytes=after['rss_bytes'],peak_rss_bytes=after['peak_rss_bytes'],status='PASS')
                                        result.update({key:after[key]-before[key] for key in ('voluntary_context_switches','involuntary_context_switches')})
                                        rows.append(result);print(json.dumps(result),flush=True)
                                    finally:
                                        if process.poll() is None:process.stdin.write('stop\n');process.stdin.flush()
                                        try:process.wait(15)
                                        except subprocess.TimeoutExpired:process.kill();process.wait();raise RuntimeError('Local benchmark worker failed to stop')
                                        (a.output/f'{transport}-{repetition}-{label}.log').write_text(log.read_text())
                                        if process.returncode:raise RuntimeError(log.read_text()[-8192:])
                                    if mode=='tun':result['final_native_metrics']=json.loads(ready.with_suffix('.metrics.json').read_text())
                        finally:app.close();tun.close()
                finally:peer.close()
        medians=[]
        for transport in a.transports:
            for label,build,_ in labels:
                group=[r for r in rows if r['transport']==transport and r['label']==label]
                medians.append(dict(label=label,transport=transport,rounds=len(group),**{key:statistics.median(r[key] for r in group) for key in ('goodput_mbit_s','rtt_ms_p50','rtt_ms_p95','cpu_seconds','rss_bytes')}))
        report={'schema':'vpn-local-native-performance-v1','status':'PASS','scope':__doc__,'provenance':{label:json.loads((build/'build-provenance.json').read_text()) for label,build,_ in labels},'measurements':rows,'medians':medians}
        (a.output/'performance-report.json').write_text(json.dumps(report,indent=2)+'\n')
    finally:core.CoreTests.tearDownClass()
if __name__=='__main__':main()
