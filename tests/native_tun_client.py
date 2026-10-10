"""Bounded synthetic TCP application for borrowed-FD tests, not an OS adapter.

The application endpoint lives outside the measured core process. It implements
window/ACK accounting, ordered receive and half-close for controlled loopback
fixtures. Benchmarks must disclose its Python scheduling/packet overhead.
"""
import itertools,socket,struct,threading,time
from test_native_tun_runtime import checksum,SRC,DST
_ports=itertools.count(33000)

class PacketTCPClient:
    def __init__(self,app):
        self.app=app;self.port=next(_ports);self.timeout=30;self.lock=threading.Condition();self.send_lock=threading.Lock()
        self.next=1001;self.ack=1001;self.window=0;self.remote=None;self.established=False;self.eof=False;self.fin=None
        self.received=bytearray();self.out_of_order={};self.limit=524288;self.error=None;self.stopped=False
        self.pending=[];self.last_byte=None;self.ack_at=time.monotonic();self.retransmissions=0
        self.app.settimeout(.25);self.reader=threading.Thread(target=self._read,name='synthetic-tcp-app');self.reader.start()
        self._send(self._packet(b'',1000,0,2))
        with self.lock:self._wait(lambda:self.established)
    def _wait(self,condition):
        deadline=time.monotonic()+self.timeout
        while not condition():
            if self.error:raise self.error
            left=deadline-time.monotonic()
            if left<=0:raise TimeoutError('synthetic TCP application deadline')
            self.lock.wait(left)
    def _free(self):return max(0,min(65535,self.limit-len(self.received)-sum(map(len,self.out_of_order.values()))))
    def _packet(self,payload,seq,ack,flags):
        segment=struct.pack('!HHIIBBHHH',self.port,443,seq&0xffffffff,ack&0xffffffff,80,flags,self._free(),0,0)+payload
        check=checksum(SRC+DST+struct.pack('!BBH',0,6,len(segment))+segment)
        segment=segment[:16]+struct.pack('!H',check)+segment[18:]
        header=struct.pack('!BBHHHBBH4s4s',69,0,20+len(segment),0,0,64,6,0,SRC,DST)
        return header[:10]+struct.pack('!H',checksum(header))+header[12:]+segment
    def _send(self,p):
        with self.send_lock:
            deadline=time.monotonic()+self.timeout
            while True:
                try:
                    if self.app.send(p)!=len(p):raise RuntimeError('partial synthetic IP datagram')
                    return
                except socket.timeout:
                    if time.monotonic()>=deadline:raise TimeoutError('synthetic packet send timeout')
    def _read(self):
        try:
            while not self.stopped:
                try:p=self.app.recv(65535)
                except socket.timeout:
                    reply=None
                    with self.lock:
                        if self.remote is not None and time.monotonic()-self.ack_at>=.25:
                            if self.pending:
                                seq,data=self.pending[0];reply=self._packet(data,seq,self.remote,24)
                            elif self.window==0 and self.last_byte is not None:
                                reply=self._packet(self.last_byte,self.next-1,self.remote,24)
                            if reply:self.ack_at=time.monotonic();self.retransmissions+=1
                    if reply:self._send(reply)
                    continue
                if len(p)<40 or p[0]>>4!=4 or p[9]!=6:continue
                ip=(p[0]&15)*4
                if len(p)<ip+20:raise RuntimeError('short TCP header')
                source,destination,seq,ack,offset,flags,window=struct.unpack('!HHIIBBH',p[ip:ip+16])
                if source!=443 or destination!=self.port:continue
                if checksum(p[:ip]) or checksum(p[12:20]+struct.pack('!BBH',0,6,len(p)-ip)+p[ip:]):raise RuntimeError('synthetic response checksum failed')
                data=p[ip+(offset>>4)*4:];reply=None
                with self.lock:
                    if flags&4:raise ConnectionResetError(f'native TCP endpoint reset; next={self.next} ack={self.ack} remote={self.remote} queued={len(self.received)} out_of_order={[(k,len(v)) for k,v in self.out_of_order.items()]}')
                    if flags&2:
                        self.remote=(seq+1)&0xffffffff;self.established=True;self.window=window
                        reply=self._packet(b'',self.next,self.remote,16)
                    elif self.remote is not None:
                        if flags&16 and self.ack<=ack<=self.next:
                            if ack>self.ack:self.ack_at=time.monotonic()
                            self.ack=ack;self.window=window
                            self.pending=[(position,payload) for position,payload in self.pending if position+len(payload)>ack]
                        if data:
                            behind=(self.remote-seq)&0xffffffff
                            if behind<len(data):data=data[behind:];seq=self.remote
                            distance=(seq-self.remote)&0xffffffff
                            if distance<self.limit and seq not in self.out_of_order:
                                if len(self.received)+sum(map(len,self.out_of_order.values()))+len(data)>self.limit:raise RuntimeError('synthetic receive memory limit')
                                self.out_of_order[seq]=data
                            while self.remote in self.out_of_order:
                                chunk=self.out_of_order.pop(self.remote);self.received.extend(chunk);self.remote=(self.remote+len(chunk))&0xffffffff
                            reply=self._packet(b'',self.next,self.remote,16)
                        if flags&1 and (seq+len(data))&0xffffffff==self.remote:
                            self.remote=(self.remote+1)&0xffffffff;self.eof=True;reply=self._packet(b'',self.next,self.remote,16)
                    self.lock.notify_all()
                if reply:self._send(reply)
        except BaseException as error:
            if not self.stopped:
                with self.lock:self.error=error;self.lock.notify_all()
    def settimeout(self,value):self.timeout=value
    def sendall(self,payload):
        position=0
        while position<len(payload):
            with self.lock:
                if self.fin is not None:raise BrokenPipeError('application send direction closed')
                self._wait(lambda:self.ack+self.window>self.next)
                n=min(1200,len(payload)-position,self.ack+self.window-self.next)
                seq=self.next;data=bytes(payload[position:position+n]);self.next+=n
                self.pending.append((seq,data));self.last_byte=data[-1:]
                if sum(len(part) for _,part in self.pending)>65535+1200:raise RuntimeError('synthetic send memory limit')
                p=self._packet(data,seq,self.remote,24)
            self._send(p);position+=n
    def recv(self,size):
        with self.lock:
            self._wait(lambda:bool(self.received) or self.eof)
            if not self.received:return b''
            data=bytes(self.received[:size]);del self.received[:size];reply=self._packet(b'',self.next,self.remote,16)
        self._send(reply);return data
    def shutdown_write(self):
        with self.lock:
            if self.fin is not None:return
            self.fin=self.next;self.next+=1;p=self._packet(b'',self.fin,self.remote,17)
        self._send(p)
    def close(self):
        try:
            self.shutdown_write()
            with self.lock:
                deadline=time.monotonic()+2
                while not self.error and not (self.eof and self.ack>=self.next) and time.monotonic()<deadline:self.lock.wait(.01)
        finally:
            self.stopped=True;self.reader.join(1)
            if self.reader.is_alive():raise RuntimeError('synthetic reader did not join')
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
