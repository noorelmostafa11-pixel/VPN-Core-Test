package hysteria1

import (
    "bytes"
    "sync"
    "time"
)
const (
    MaxPendingPackets=8
    MaxPendingBytes=128*1024
    FragmentTTL=5*time.Second
)
type Datagram struct{SessionID uint32;Host string;Port uint16;Payload []byte}
type assemblyKey struct{session uint32;packet uint16}
type partialPacket struct{
    host string
    port uint16
    parts [][]byte
    filled,bytes int
    created time.Time
}
// Assembler has bounded per-peer incomplete fragment memory.
type Assembler struct{
    mu sync.Mutex
    pending map[assemblyKey]*partialPacket
    pendingBytes int
    clock func()time.Time
}
func NewAssembler()*Assembler{return &Assembler{clock:time.Now}}
func(a *Assembler)expire(now time.Time){
    for k,p:=range a.pending{
        if now.Sub(p.created)>=FragmentTTL{
            a.pendingBytes-=p.bytes
            delete(a.pending,k)
        }
    }
}
func(a *Assembler)Feed(f UDPFrame)(Datagram,bool,error){
    if !validAddress(f.Host,f.Port,false)||f.FragmentCount==0||f.FragmentCount>MaxFragments||
        f.FragmentIndex>=f.FragmentCount||(f.FragmentCount>1&&f.PacketID==0)||len(f.Payload)>MaxUDPPayload{
        return Datagram{},false,ErrWire
    }
    if f.FragmentCount==1{
        return Datagram{SessionID:f.SessionID,Host:f.Host,Port:f.Port,Payload:append([]byte(nil),f.Payload...)},true,nil
    }
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.clock==nil{a.clock=time.Now}
    if a.pending==nil{a.pending=make(map[assemblyKey]*partialPacket)}
    a.expire(a.clock())
    k:=assemblyKey{f.SessionID,f.PacketID}
    p:=a.pending[k]
    if p==nil{
        if len(a.pending)>=MaxPendingPackets{return Datagram{},false,ErrWire}
        p=&partialPacket{host:f.Host,port:f.Port,parts:make([][]byte,int(f.FragmentCount)),created:a.clock()}
        a.pending[k]=p
    }
    if p.host!=f.Host||p.port!=f.Port||len(p.parts)!=int(f.FragmentCount){return Datagram{},false,ErrWire}
    if p.parts[f.FragmentIndex]!=nil{return Datagram{},false,nil}
    if p.bytes+len(f.Payload)>MaxUDPPayload||a.pendingBytes+len(f.Payload)>MaxPendingBytes{return Datagram{},false,ErrWire}
    p.parts[f.FragmentIndex]=append([]byte{},f.Payload...)
    if p.parts[f.FragmentIndex]==nil{p.parts[f.FragmentIndex]=[]byte{}}
    p.bytes+=len(f.Payload)
    p.filled++
    a.pendingBytes+=len(f.Payload)
    if p.filled!=len(p.parts){return Datagram{},false,nil}
    data:=make([]byte,0,p.bytes)
    for _,part:=range p.parts{data=append(data,part...)}
    a.pendingBytes-=p.bytes
    delete(a.pending,k)
    return Datagram{SessionID:f.SessionID,Host:f.Host,Port:f.Port,Payload:data},true,nil
}
func(a *Assembler)Close(){
    a.mu.Lock()
    clear(a.pending)
    a.pendingBytes=0
    a.mu.Unlock()
}
func CanonicalFrame(data []byte)(UDPFrame,error){
    f,err:=ParseUDPFrame(data)
    if err!=nil{return UDPFrame{},err}
    roundtrip,err:=f.MarshalBinary()
    if err!=nil||!bytes.Equal(roundtrip,data){return UDPFrame{},ErrWire}
    return f,nil
}
