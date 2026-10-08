"""Real A/AAAA queries forwarded through VLESS UDP to an independent DNS server."""
import ipaddress,socket,struct,threading,unittest
import test_core as core
import test_expanded as old
import test_udp_sdk as sdk
class DnsServer:
    def __init__(self,family):
        self.socket=socket.socket(family,socket.SOCK_DGRAM);self.socket.bind(('::1' if family==socket.AF_INET6 else '127.0.0.1',0));self.port=self.socket.getsockname()[1];self.socket.settimeout(.1);self.stop=threading.Event();self.received=[];self.errors=[]
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while not self.stop.is_set():
            try:data,source=self.socket.recvfrom(4096)
            except socket.timeout:continue
            except OSError:return
            try:
                self.received.append((data,source));kind,cls=struct.unpack('!HH',data[-4:]);assert kind in (1,28) and cls==1
                address=ipaddress.ip_address('192.0.2.123' if kind==1 else '2001:db8::123').packed
                reply=data[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+data[12:]+b'\xc0\x0c'+struct.pack('!HHIH',kind,1,60,len(address))+address
                self.socket.sendto(reply,source)
            except Exception as e:self.errors.append(type(e).__name__)
    def close(self):self.stop.set();self.socket.close();self.thread.join(2)
class ForwardPeer(old.Peer):
    def handle(self,raw):
        try:
            raw.settimeout(4)
            if core.exact(raw,19)!=b'\0'+old.ID.bytes+b'\0\2':raise ValueError('VLESS UDP')
            port=int.from_bytes(core.exact(raw,2),'big');kind=core.exact(raw,1)
            host=socket.inet_ntop(socket.AF_INET if kind==b'\1' else socket.AF_INET6,core.exact(raw,4 if kind==b'\1' else 16))
            with socket.socket(socket.AF_INET if kind==b'\1' else socket.AF_INET6,socket.SOCK_DGRAM) as target:
                target.settimeout(2);target.connect((host,port));self.target_source=target.getsockname()
                raw.sendall(b'\0\0')
                while True:
                    length=int.from_bytes(core.exact(raw,2),'big');data=core.exact(raw,length);target.send(data);answer=target.recv(4096);raw.sendall(len(answer).to_bytes(2,'big')+answer)
        except (EOFError,OSError):pass
        except Exception as e:self.errors.append(type(e).__name__)
        finally:raw.close()
class DnsAcceptanceTests(unittest.TestCase):
    setUpClass=classmethod(sdk.UdpSdkTests.setUpClass.__func__)
    tearDownClass=classmethod(sdk.UdpSdkTests.tearDownClass.__func__)
    engine=sdk.UdpSdkTests.engine;association=sdk.UdpSdkTests.association
    def exchange(self,family):
        dns=DnsServer(family);peer=ForwardPeer('vless')
        try:
            with self.engine(f'vless://{old.ID}@127.0.0.1:{peer.port}?security=none&type=raw') as (port,log):
                control,client,relay=self.association(port)
                try:
                    address=(b'\4'+ipaddress.ip_address('::1').packed if family==socket.AF_INET6 else b'\1\x7f\0\0\1')+dns.port.to_bytes(2,'big')
                    for kind in (1,28):
                        query=kind.to_bytes(2,'big')+struct.pack('!HHHHH',0x0100,1,0,0,0)+b'\x07example\x04test\0'+struct.pack('!HH',kind,1)
                        client.sendto(b'\0\0\0'+address+query,relay);response=client.recvfrom(4096)[0]
                        self.assertEqual(response[:3+len(address)],b'\0\0\0'+address);answer=response[3+len(address):]
                        self.assertEqual(answer[:2],query[:2]);self.assertEqual(answer[2:4],b'\x81\x80')
                        wanted=ipaddress.ip_address('192.0.2.123' if kind==1 else '2001:db8::123').packed;self.assertEqual(answer[-len(wanted):],wanted)
                    self.assertEqual(len(dns.received),2)
                    for _,source in dns.received:self.assertEqual(source[1],peer.target_source[1])
                    self.assertEqual(peer.errors,[]);self.assertEqual(dns.errors,[])
                finally:control.close();client.close()
        finally:peer.close();dns.close()
    def test_a_and_aaaa_over_udp_proxy(self):self.exchange(socket.AF_INET)
    def test_ipv6_dns_destination_over_udp_proxy(self):
        if not socket.has_ipv6:self.skipTest('IPv6 unavailable')
        self.exchange(socket.AF_INET6)
