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
    def __init__(self,crypto,seed=None,loss=False,mtu=900):
        self.crypto=crypto;self.seed=seed;self.loss=loss;self.mtu=mtu;self.errors=[];self.dropped=0;self.retransmitted=0;self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.socket.bind(('127.0.0.1',0));self.socket.settimeout(.01);self.port=self.socket.getsockname()[1];self.stop=threading.Event();self.sessions={};self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def seal(self,data):
        if self.seed is not None:
            nonce=os.urandom(12);return nonce+AESGCM(hashlib.sha256(self.seed.encode()).digest()[:16]).encrypt(nonce,data,None)
        body=struct.pack('!H',len(data))+data;wire=bytearray(struct.pack('!I',fnv(body))+body)
        for i in range(4,len(wire)):wire[i]^=wire[i-4]
        return wire
    def open(self,data):
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
    def exchange(self,protocol='vless',cipher='',seed=None,loss=False,tls=False,connections=1):
        crypto=old.Peer(protocol,cipher,tls_context=self.context if tls else None);peer=KCPPeer(crypto,seed,loss)
        try:
            credential=str(old.ID) if protocol in ('vless','vmess') else old.SECRET
            if protocol=='ss':credential=__import__('base64').urlsafe_b64encode((cipher+':'+old.SECRET).encode()).decode().rstrip('=')
            uri=f'{protocol}://{credential}@127.0.0.1:{peer.port}?type=kcp&security={"tls" if tls else "none"}&sni=localhost&mtu=900&tti=20'
            if protocol=='vmess':uri+='&encryption='+cipher
            if seed is not None:uri+='&seed='+seed
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
if __name__=='__main__':unittest.main(verbosity=2)
