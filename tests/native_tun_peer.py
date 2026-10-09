"""Independent controlled TLS + VLESS/Trojan TCP/UDP peer for OS TUN tests."""
import hashlib,socket,ssl,struct,threading
import test_core as core
import test_expanded as peers
from test_udp_sdk import address
class NativeTunPeer(peers.Peer):
    def __init__(self,protocol,cipher='',transport='raw',tls_context=None,corrupt=False,path='/test/Tun',bind_address=None):
        if bind_address is None:
            super().__init__(protocol,cipher,transport,tls_context,corrupt,path);return
        self.protocol,self.cipher,self.transport=protocol,cipher,transport
        self.tls_context,self.corrupt,self.path=tls_context,corrupt,path
        self.listener=socket.socket(socket.AF_INET6 if ':' in bind_address else socket.AF_INET)
        self.listener.bind((bind_address,0));self.port=self.listener.getsockname()[1]
        self.listener.listen(64);self.listener.settimeout(.2)
        self.stop=threading.Event();self.errors=[];self.accepted=0
        self.thread=threading.Thread(target=self.accept,daemon=True);self.thread.start()
    def handle(self,raw):
        sock=raw
        try:
            raw.settimeout(15);sock=self.tls_context.wrap_socket(raw,server_side=True) if self.tls_context else raw
            wire=peers.Wrapped(sock,self.transport,path=self.path)
            if self.protocol=='vless':
                if core.exact(wire,18)!=b'\0'+peers.ID.bytes+b'\0':raise ValueError('VLESS identity')
                command=core.exact(wire,1)[0];core.exact(wire,2);kind=core.exact(wire,1)[0]
                core.exact(wire,4 if kind==1 else 16 if kind==3 else core.exact(wire,1)[0]);wire.sendall(b'\0\0')
                udp=command==2
            elif self.protocol=='trojan':
                if core.exact(wire,56)!=hashlib.sha224(peers.SECRET.encode()).hexdigest().encode() or core.exact(wire,2)!=b'\r\n':raise ValueError('Trojan identity')
                command=core.exact(wire,1)[0];address(wire)
                if core.exact(wire,2)!=b'\r\n':raise ValueError('Trojan delimiter')
                udp=command==3
            else:raise ValueError('fixture protocol')
            self.accepted+=1
            if not udp:
                wire.sendall(peers.HELLO)
                while True:
                    payload=wire.recv(16384)
                    if not payload:break
                    wire.sendall(payload)
            elif self.protocol=='vless':
                while True:
                    size=core.exact(wire,2);payload=core.exact(wire,int.from_bytes(size,'big'));wire.sendall(size+payload)
            else:
                while True:
                    dest=address(wire);size=core.exact(wire,2)
                    if core.exact(wire,2)!=b'\r\n':raise ValueError('UDP delimiter')
                    payload=core.exact(wire,int.from_bytes(size,'big'));wire.sendall(dest+size+b'\r\n'+payload)
        except (EOFError,OSError,ssl.SSLError):pass
        except Exception as error:self.errors.append(repr(error))
        finally:sock.close();raw.close()
