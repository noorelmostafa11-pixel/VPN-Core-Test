package hysteria1

import (
    "bytes"
    "net"
    "testing"
    "time"
)
func TestXPlusUDPRoundTrip(t *testing.T){
    rawA,err:=net.ListenPacket("udp","127.0.0.1:0")
    if err!=nil{t.Fatal(err)}
    defer rawA.Close()
    rawB,err:=net.ListenPacket("udp","127.0.0.1:0")
    if err!=nil{t.Fatal(err)}
    defer rawB.Close()
    a,_:=NewXPlusPacketConn(rawA,[]byte("synthetic-key"))
    b,_:=NewXPlusPacketConn(rawB,[]byte("synthetic-key"))
    _=a.SetDeadline(time.Now().Add(time.Second*2))
    _=b.SetDeadline(time.Now().Add(time.Second*2))
    payload:=bytes.Repeat([]byte("udp"),300)
    if _,err:=a.WriteTo(payload,b.LocalAddr());err!=nil{t.Fatal(err)}
    recv:=make([]byte,4096)
    n,addr,err:=b.ReadFrom(recv)
    if err!=nil||!bytes.Equal(recv[:n],payload){t.Fatal(err)}
    if _,err=b.WriteTo(recv[:n],addr);err!=nil{t.Fatal(err)}
    n,_,err=a.ReadFrom(recv)
    if err!=nil||!bytes.Equal(recv[:n],payload){t.Fatal(err)}
}
