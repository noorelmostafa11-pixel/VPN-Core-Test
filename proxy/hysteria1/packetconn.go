package hysteria1

import (
    "io"
    "net"
    "sync"
    "time"
)
// PacketConn optionally carries Hysteria v1 xplus over a separate UDP socket.
type PacketConn struct{
    raw net.PacketConn
    key []byte
    readMu sync.Mutex
    writeMu sync.Mutex
    buf []byte
}
func NewXPlusPacketConn(raw net.PacketConn,key []byte)(*PacketConn,error){
    if raw==nil||len(key)==0||len(key)>4096{return nil,ErrWire}
    return &PacketConn{raw:raw,key:append([]byte(nil),key...),buf:make([]byte,65535)},nil
}
func(p *PacketConn)ReadFrom(b []byte)(int,net.Addr,error){
    p.readMu.Lock()
    defer p.readMu.Unlock()
    for{
        n,addr,err:=p.raw.ReadFrom(p.buf)
        if err!=nil{return 0,addr,err}
        plain,err:=XPlusDecode(p.key,p.buf[:n])
        if err!=nil{continue}
        if len(plain)>len(b){return 0,addr,io.ErrShortBuffer}
        return copy(b,plain),addr,nil
    }
}
func(p *PacketConn)WriteTo(b []byte,addr net.Addr)(int,error){
    if len(b)==0||len(b)>65519{return 0,ErrWire}
    wire,err:=XPlusRandom(p.key,b)
    if err!=nil{return 0,err}
    p.writeMu.Lock()
    n,err:=p.raw.WriteTo(wire,addr)
    p.writeMu.Unlock()
    if err!=nil{return 0,err}
    if n!=len(wire){return 0,io.ErrShortWrite}
    return len(b),nil
}
func(p *PacketConn)Close()error{return p.raw.Close()}
func(p *PacketConn)LocalAddr()net.Addr{return p.raw.LocalAddr()}
func(p *PacketConn)SetDeadline(t time.Time)error{return p.raw.SetDeadline(t)}
func(p *PacketConn)SetReadDeadline(t time.Time)error{return p.raw.SetReadDeadline(t)}
func(p *PacketConn)SetWriteDeadline(t time.Time)error{return p.raw.SetWriteDeadline(t)}
var _ net.PacketConn=(*PacketConn)(nil)
