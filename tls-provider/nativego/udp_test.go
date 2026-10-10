package nativego

import (
 "bytes"
 "context"
 "encoding/binary"
 "errors"
 "io"
 "net"
 "net/netip"
 "testing"
)

func TestGoUDPCommandSelection(t *testing.T){
 var uuid [16]byte
 target:=netip.MustParseAddrPort("1.2.3.4:53")
 vless:=vlessUDPRequest(uuid,target)
 if vless[18]!=2{t.Fatalf("VLESS UDP command %d, want 2",vless[18])}
 trojan:=trojanUDPRequest("0123456789abcdef",target)
 if trojan[18]!=3{t.Fatalf("Trojan UDP command %d, want 3",trojan[18])}
}

func TestGoVLESSUDPRecordBoundary(t *testing.T){
 left,right:=net.Pipe()
 defer left.Close()
 defer right.Close()
 session:=&DatagramSession{conn:left,target:netip.MustParseAddrPort("[2001:db8::53]:53"),protocol:"vless"}
 payload:=[]byte{1,2,3,4,0,5}
 done:=make(chan error,1)
 go func(){done<-session.WriteDatagram(payload)}()
 wire:=make([]byte,len(payload)+2)
 if _,err:=io.ReadFull(right,wire);err!=nil{t.Fatal(err)}
 if int(binary.BigEndian.Uint16(wire[:2]))!=len(payload)||!bytes.Equal(wire[2:],payload){t.Fatalf("incorrect VLESS UDP frame: %x",wire)}
 if err:=<-done;err!=nil{t.Fatal(err)}
 go func(){_,_=right.Write(wire)}()
 output,err:=session.ReadDatagram()
 if err!=nil||!bytes.Equal(output,payload){t.Fatalf("VLESS UDP read: %x %v",output,err)}
}

func TestGoTrojanUDPRejectsIncorrectReplyEndpoint(t *testing.T){
 left,right:=net.Pipe()
 defer left.Close()
 defer right.Close()
 session:=&DatagramSession{conn:left,target:netip.MustParseAddrPort("1.2.3.4:53"),protocol:"trojan"}
 go func(){_,_=right.Write([]byte{1,1,2,3,5,0,53,0,1,'\r','\n',42})}()
 if _,err:=session.ReadDatagram();err==nil{t.Fatal("accepted wrong UDP reply destination")}
}

func TestGoTrojanUDPFraming(t *testing.T){
 left,right:=net.Pipe()
 defer left.Close()
 defer right.Close()
 session:=&DatagramSession{conn:left,target:netip.MustParseAddrPort("1.2.3.4:443"),protocol:"trojan"}
 done:=make(chan error,1)
 go func(){done<-session.WriteDatagram([]byte("hello"))}()
 want:=[]byte{1,1,2,3,4,1,187,0,5,'\r','\n','h','e','l','l','o'}
 got:=make([]byte,len(want))
 if _,err:=io.ReadFull(right,got);err!=nil{t.Fatal(err)}
 if !bytes.Equal(got,want){t.Fatalf("Trojan UDP frame: %x != %x",got,want)}
 if err:=<-done;err!=nil{t.Fatal(err)}
 go func(){_,_=right.Write(want)}()
 payload,err:=session.ReadDatagram()
 if err!=nil||string(payload)!="hello"{t.Fatalf("Trojan UDP read: %q %v",payload,err)}
}

func TestGoUDPFailClosedOnOversizeAndMissingProtection(t *testing.T){
 s:=&DatagramSession{target:netip.MustParseAddrPort("1.2.3.4:53"),protocol:"vless"}
 if err:=s.WriteDatagram(make([]byte,65508));err==nil{t.Fatal("oversized IPv4 payload accepted")}
 d:=&Dialer{}
 if _,err:=d.DialDatagram(context.Background(),s.target);!errors.Is(err,ErrUnprotected){t.Fatalf("unprotected node dial admitted: %v",err)}
}
