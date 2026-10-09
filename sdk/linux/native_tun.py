#!/usr/bin/env python3
"""Managed Linux Native TUN host with persistent, owned nftables kill switch.

Run as root (CAP_NET_ADMIN). No global DNS/default-route snapshots are restored:
only this ephemeral TUN's addresses, split defaults, per-link DNS and nft table
are owned. A process crash drops the ephemeral device/routes but leaves the
firewall fail closed. --recover removes only the named table with its marker.
"""
import argparse,fcntl,ipaddress,json,os,pathlib,signal,socket,subprocess,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'native'))
from tun_host import TunHost
TABLE='vpncore_native_v1';MARK=0x56504e;COMMENT='vpn-core-native-tun-owned-v1'
def command(*argv,input=None):
    return subprocess.run(list(argv),input=input,text=True,capture_output=True,check=True).stdout
class LinuxPolicy:
    def __init__(self,name,addresses,port,dns=('9.9.9.9','2620:fe::fe'),endpoints=None):
        if not name.isalnum() or len(name)>15:raise ValueError('Use a unique alphanumeric interface name')
        self.name=name;self.addresses=tuple(ipaddress.ip_address(a) for a in addresses);self.port=int(port);self.endpoints=tuple((ipaddress.ip_address(ip),int(p)) for ip,p in (endpoints or [(ip,self.port) for ip in self.addresses]));self.dns=dns;self.acquired=False
        if any(not 1<=p<=65535 for _,p in self.endpoints):raise ValueError("Invalid bootstrap port")
    @staticmethod
    def recover():
        result=subprocess.run(['nft','-j','list','table','inet',TABLE],capture_output=True,text=True)
        if result.returncode:return
        if COMMENT not in result.stdout:raise RuntimeError('Refusing to remove unowned nftables table')
        command('nft','delete','table','inet',TABLE)
    def acquire(self):
        old=subprocess.run(['nft','list','table','inet',TABLE],capture_output=True)
        if old.returncode==0:raise RuntimeError('Previous fail-closed policy remains; inspect then use --recover')
        allow=[]
        for ip,port in self.endpoints:
            family='ip6' if ip.version==6 else 'ip'
            allow.append(f'{family} daddr {ip} meta mark {MARK} meta l4proto {{ tcp, udp }} th dport {port} accept')
        # Atomic nft batch: no transient accept-all chain or flush of other rules.
        text=f'''table inet {TABLE} {{
 comment "{COMMENT}"
 chain output {{
 type filter hook output priority -150; policy drop;
 oifname "lo" accept
 oifname "{self.name}" accept
 ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type {{ 133, 135, 136 }} icmpv6 code 0 accept
 ip6 daddr ff02::/16 ip6 hoplimit 1 meta l4proto ipv6-icmp icmpv6 type {{ 131, 132, 143 }} icmpv6 code 0 accept
 {'; '.join(allow)}
 counter drop
 }}
}}\n'''
        command('nft','-f','-',input=text);self.acquired=True
    def configure(self):
        command('ip','link','set','dev',self.name,'mtu','1500','up')
        command('ip','address','add','198.18.0.2/30','dev',self.name)
        command('ip','-6','address','add','fd71:5650::2/126','dev',self.name,'nodad')
        for prefix in ('0.0.0.0/1','128.0.0.0/1'):command('ip','route','add',prefix,'dev',self.name,'metric','5')
        for prefix in ('::/1','8000::/1'):command('ip','-6','route','add',prefix,'dev',self.name,'metric','5')
        # systemd-resolved link-scoped state disappears with the owned interface.
        # Fail startup on unsupported DNS manager instead of silently leaking.
        command('resolvectl','dns',self.name,*self.dns)
        command('resolvectl','domain',self.name,'~.')
        command('resolvectl','default-route',self.name,'yes')
    def close(self):
        if self.acquired:self.recover();self.acquired=False

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=pathlib.Path);p.add_argument('--config',type=pathlib.Path)
    p.add_argument('--node-host');p.add_argument('--node-port',type=int);p.add_argument('--uplink',help='Existing physical interface; sockets are pinned before connect')
    p.add_argument('--name',default='vpncoretun');p.add_argument('--recover',action='store_true');p.add_argument('--dns',nargs='+',default=['9.9.9.9','2620:fe::fe']);a=p.parse_args()
    if os.geteuid()!=0:p.error('Administrative network privileges required')
    lock=open('/run/vpn-core-native-tun.lock','w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if a.recover:LinuxPolicy.recover();return
    if not all((a.build,a.config,a.node_host,a.node_port,a.uplink)):p.error('--build --config --node-host --node-port --uplink required')
    socket.if_nametoindex(a.uplink)
    addresses={};endpoints=[]
    def protect(fd):
        with socket.socket(fileno=os.dup(fd)) as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,a.uplink.encode()+b'\0');s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,MARK)
        return True
    def resolve(host):
        if host not in addresses:raise RuntimeError('Bootstrap hostname was not pinned before routing')
        return addresses[host]
    host=TunHost(a.build,a.config,name=a.name,protect=protect,resolve=resolve)
    targets=host.bootstrap_targets()
    if not targets or targets[0]!={'host':a.node_host,'port':a.node_port}:p.error('Primary host/port must match the original parsed node')
    for target in targets:
        name=target['host'];port=target['port']
        if name not in addresses:addresses[name]=sorted({r[4][0] for r in socket.getaddrinfo(name,port,type=socket.SOCK_STREAM)})
        endpoints.extend((ip,port) for ip in addresses[name])
    policy=LinuxPolicy(a.name,addresses[a.node_host],a.node_port,tuple(a.dns),endpoints=endpoints)
    def stop(signum,frame):host.request_stop()
    signal.signal(signal.SIGINT,stop);signal.signal(signal.SIGTERM,stop)
    normal=False
    try:
        policy.acquire();host.start();policy.configure();print('Native TUN ready; strict kill switch active',flush=True)
        while host.thread.is_alive():host.drain();time.sleep(.05)
        normal=host.result==0
    finally:
        result=host.stop()
        if normal or result==0:policy.close()
        else:print('Core failed: network remains blocked. Disconnect with --recover.',file=sys.stderr)
if __name__=='__main__':main()
