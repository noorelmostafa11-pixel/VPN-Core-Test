"""Independent UDP mKCP codec/ARQ fixture relaying to the crypto oracle."""
import concurrent.futures,hashlib,hmac,os,random,socket,struct,threading,time,unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import test_expanded as old
from test_core import exact

def fnv(data):
    value=2166136261
    for b in data:value=((value^b)*16777619)&0xffffffff
    return value
class KCPPeer:
    def __init__(self,crypto,seed=None,loss=False,mtu=900,header='none'):
        self.header=header;self.header_size={'none':0,'srtp':4,'utp':4,'wireguard':4,'dtls':13,'wechat-video':13,'dns':33}[header]
        self.crypto=crypto;self.seed=seed;self.loss=loss;self.mtu=mtu;self.errors=[];self.dropped=0;self.retransmitted=0;self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.socket.bind(('127.0.0.1',0));self.socket.settimeout(.01);self.port=self.socket.getsockname()[1];self.stop=threading.Event();self.sessions={};self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def seal(self,data):
        prefix={'none':b'','srtp':b'\xb5\xe8\x00\x01','utp':b'\x12\x34\x01\x00','wireguard':b'\x04\x00\x00\x00',
                'dtls':b'\x17\xfe\xfd'+bytes(10),'wechat-video':b'\xa1\x08'+bytes(4)+b'\x00\x10\x11\x18\x30\x22\x30',
                'dns':b'\x12\x34\x01\x00\x00\x01'+bytes(6)+b'\x03www\x07example\x03com\x00\x00\x01\x00\x01'}[self.header]
        if self.seed is not None:
            nonce=os.urandom(12);return prefix+nonce+AESGCM(hashlib.sha256(self.seed.encode()).digest()[:16]).encrypt(nonce,data,None)
        body=struct.pack('!H',len(data))+data;wire=bytearray(struct.pack('!I',fnv(body))+body)
        for i in range(4,len(wire)):wire[i]^=wire[i-4]
        return prefix+wire
    def open(self,data):
        if len(data)>self.mtu:raise ValueError('MTU exceeded by header')
        if self.header=='srtp' and data[:2]!=b'\xb5\xe8':raise ValueError('SRTP prefix')
        if self.header=='utp' and data[2:4]!=b'\x01\x00':raise ValueError('uTP prefix')
        if self.header=='wireguard' and data[:4]!=b'\x04\x00\x00\x00':raise ValueError('WireGuard prefix')
        if self.header=='dtls' and data[:3]!=b'\x17\xfe\xfd':raise ValueError('DTLS prefix')
        if self.header=='wechat-video' and (data[:2]!=b'\xa1\x08' or data[6:13]!=b'\x00\x10\x11\x18\x30\x22\x30'):raise ValueError('WeChat prefix')
        if self.header=='dns' and data[2:self.header_size]!=b'\x01\x00\x00\x01'+bytes(6)+b'\x03www\x07example\x03com\x00\x00\x01\x00\x01':raise ValueError('DNS prefix')
        data=data[self.header_size:]
        if self.seed is not None:return AESGCM(hashlib.sha256(self.seed.encode()).digest()[:16]).decrypt(data[:12],data[12:],None)
        wire=bytearray(data)
        for i in range(len(wire)-1,3,-1):wire[i]^=wire[i-4]
        if len(wire)<6 or fnv(wire[4:])!=int.from_bytes(wire[:4],'big') or len(wire)-6!=int.from_bytes(wire[4:6],'big'):raise ValueError('checksum')
        return wire[6:]
    def send(self,s,cmd,body,opt=0):self.socket.sendto(self.seal(struct.pack('!HBB',s['conv'],cmd,opt)+body),s['address'])
    def target(self,s):
        try:
            while not self.stop.is_set():
                data=s['tcp'].recv(16384)
                if not data:break
                with s['lock']:
                    for start in range(0,len(data),self.mtu-64):
                        n=s['send'];s['send']+=1;s['pending'][n]=[data[start:start+self.mtu-64],0,0]
        except OSError:pass
        finally:s['ended']=True
    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    wire,address=self.socket.recvfrom(65536)
                    try:data=self.open(wire)
                    except Exception:continue
                    if len(data)<4:continue
                    conv,cmd,opt=struct.unpack('!HBB',data[:4]);data=data[4:];key=(address,conv)
                    if key not in self.sessions:
                        tcp=socket.create_connection(('127.0.0.1',self.crypto.port),5);tcp.settimeout(15)
                        s=dict(conv=conv,address=address,tcp=tcp,next=0,send=0,received={},pending={},lock=threading.Lock(),dropped=set(),ended=False,closed=False);self.sessions[key]=s;threading.Thread(target=self.target,args=(s,),daemon=True).start()
                    s=self.sessions[key]
                    if cmd==1:
                        timestamp,number,first,size=struct.unpack('!IIIH',data[:14]);payload=data[14:14+size]
                        if len(payload)!=size:raise ValueError('data length')
                        if self.loss and number%7==2 and number not in s['dropped']:s['dropped'].add(number);self.dropped+=1;continue
                        if number>=s['next']:s['received'].setdefault(number,payload)
                        while s['next'] in s['received']:s['tcp'].sendall(s['received'].pop(s['next']));s['next']+=1
                        self.send(s,0,struct.pack('!IIIBI',s['next']+128,s['next'],timestamp,1,number))
                        if self.loss and number%5==1:self.send(s,0,struct.pack('!IIIBI',s['next']+128,s['next'],timestamp,1,number))
                    elif cmd==0:
                        window,nextnum,timestamp,count=struct.unpack('!IIIB',data[:13]);acked=set(struct.unpack('!'+str(count)+'I',data[13:13+count*4])) if count else set()
                        with s['lock']:
                            for n in list(s['pending']):
                                if n<nextnum or n in acked:del s['pending'][n]
                    elif cmd in (2,3) and opt&1 and not s['closed']:
                        first,received,rto=struct.unpack('!III',data[:12])
                        if first<=s['next']:s['tcp'].shutdown(socket.SHUT_WR);s['closed']=True
                except socket.timeout:pass
                for s in list(self.sessions.values()):
                    with s['lock']:
                        items=list(s['pending'].items())
                        if self.loss:items=list(reversed(items))
                        for n,value in items[:64]:
                            payload,sent,tries=value
                            if time.monotonic()-sent<.10:continue
                            if tries:self.retransmitted+=1
                            value[1],value[2]=time.monotonic(),tries+1
                            if self.loss and n%9==3 and tries==0:self.dropped+=1;continue
                            first=min(s['pending']) if s['pending'] else s['send']
                            body=struct.pack('!IIIH',int(time.monotonic()*1000)&0xffffffff,n,first,len(payload))+payload
                            self.send(s,1,body)
                        if s['ended'] and not s['pending']:self.send(s,2,struct.pack('!III',s['send'],s['next'],300),1)
        except OSError:
            if not self.stop.is_set():self.errors.append('UDP socket failure')
        except Exception as e:self.errors.append(repr(e))
    def close(self):
        self.stop.set();self.socket.close();self.thread.join(2)
        for s in self.sessions.values():s['tcp'].close()

class MKCPTests(unittest.TestCase):
    setUpClass=classmethod(old.ExpandedTests.setUpClass.__func__);tearDownClass=classmethod(old.ExpandedTests.tearDownClass.__func__)
    core=old.ExpandedTests.core;socks=old.ExpandedTests.socks
    def exchange(self,protocol='vless',cipher='',seed=None,loss=False,tls=False,connections=1,header='none'):
        crypto=old.Peer(protocol,cipher,tls_context=self.context if tls else None);peer=KCPPeer(crypto,seed,loss,header=header)
        try:
            credential=str(old.ID) if protocol in ('vless','vmess') else old.SECRET
            if protocol=='ss':credential=__import__('base64').urlsafe_b64encode((cipher+':'+old.SECRET).encode()).decode().rstrip('=')
            uri=f'{protocol}://{credential}@127.0.0.1:{peer.port}?type=kcp&security={"tls" if tls else "none"}&sni=localhost&mtu=900&tti=20'
            if protocol=='vmess':uri+='&encryption='+cipher
            if seed is not None:uri+='&seed='+seed
            uri+='&headerType='+header
            if tls:uri+='&fp=chrome'
            with self.core(uri) as (port,log):
                def run(i):
                    with self.socks(port) as s:
                        self.assertEqual(exact(s,len(old.HELLO)),old.HELLO);data=random.Random(i).randbytes(190001)
                        with concurrent.futures.ThreadPoolExecutor() as pool:
                            f=pool.submit(s.sendall,data);self.assertEqual(hashlib.sha256(exact(s,len(data))).digest(),hashlib.sha256(data).digest());f.result(10)
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(run,range(connections)))
                self.assertNotIn('failed phase=',log.read_text())
            self.assertEqual(peer.errors+crypto.errors,[])
            if loss:self.assertGreater(peer.dropped,0);self.assertGreater(peer.retransmitted,0)
        finally:peer.close();crypto.close()
    def test_01_four_protocols(self):
        for protocol,cipher in [('vless',''),('vmess','aes-128-gcm'),('trojan',''),('ss','chacha20-ietf-poly1305')]:
            with self.subTest(protocol=protocol):self.exchange(protocol,cipher)
    def test_02_loss_reordering_duplication(self):self.exchange(loss=True,connections=8)
    def test_03_seed_and_verified_tls(self):self.exchange(seed='synthetic-seed',tls=True,connections=2)
    def test_04_packet_headers_four_protocols(self):
        for header in ('srtp','utp','dtls','wechat-video','wireguard','dns'):
            for protocol,cipher in [('vless',''),('vmess','aes-128-gcm'),('trojan',''),('ss','chacha20-ietf-poly1305')]:
                with self.subTest(header=header,protocol=protocol):self.exchange(protocol,cipher,header=header)
    def test_05_headers_seed_loss_and_verified_tls(self):
        for header in ('srtp','utp','dtls','wechat-video','wireguard','dns'):
            with self.subTest(header=header):self.exchange(header=header,seed='synthetic-seed',loss=True,tls=True,connections=2)
if __name__=='__main__':unittest.main(verbosity=2)
