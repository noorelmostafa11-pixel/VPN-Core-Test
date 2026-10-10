package nativego
import (
 "bytes"
 "context"
 "errors"
 "io"
 "net"
 "net/netip"
 "testing"
)
func TestUnprotectedFailsClosed(t *testing.T){
 _,err:=NewDialer(Node{Protocol:"vless"},nil)
 if !errors.Is(err,ErrUnprotected){t.Fatalf("expected protected dial, got %v",err)}
}
func TestUnsupportedFeaturesFailClosed(t *testing.T){
 good:=Node{Protocol:"vless",Address:"203.0.113.1",Port:443,ServerName:"example.com",Security:"tls",Transport:"raw",UUID:"00112233-4455-6677-8899-aabbccddeeff"}
 cases:=[]Node{}
 a:=good;a.Security="reality";cases=append(cases,a)
 a=good;a.Transport="grpc";cases=append(cases,a)
 a=good;a.Flow="xtls-rprx-vision";cases=append(cases,a)
 a=good;a.Protocol="vmess";cases=append(cases,a)
 a=good;a.Protocol="ss";cases=append(cases,a)
 a=good;a.Encryption="mlkem768x25519plus";cases=append(cases,a)
 for _,n:=range cases{
  called:=false
  _,err:=NewDialer(n,func(context.Context,string,string)(net.Conn,error){called=true;return nil,nil})
  if !errors.Is(err,ErrUnsupported)||called{t.Fatalf("unexpected accept/dial %+v %v",n,err)}
 }
}
func TestVLESSWireIPv4IPv6(t *testing.T){
 var id [16]byte
 copy(id[:],[]byte{1,2,3,4})
 v4:=vlessRequest(id,netip.MustParseAddrPort("1.2.3.4:443"))
 want:=append([]byte{0,1,2,3,4},make([]byte,12)...)
 want=append(want,0,1,1,187,1,1,2,3,4)
 if !bytes.Equal(v4,want){t.Fatalf("wrong VLESS wire: %x vs %x",v4,want)}
 v6:=vlessRequest(id,netip.MustParseAddrPort("[2001:db8::1]:53"))
 if len(v6)!=38||v6[21]!=3 {t.Fatalf("wrong IPv6 header %x",v6)}
}
func TestTrojanWire(t *testing.T){
 d:=trojanRequest("0123456789abcdef",netip.MustParseAddrPort("1.2.3.4:443"))
 if !bytes.Equal(d,append([]byte("0123456789abcdef\r\n\x01\x01\x01\x02\x03\x04\x01\xbb"),'\r','\n')){t.Fatalf("wrong Trojan header %x",d)}
}
func TestVLESSResponseConsume(t *testing.T){
 client,server:=net.Pipe();defer client.Close();defer server.Close()
 go func(){_,_=server.Write([]byte{0,2,0xde,0xad,'o','k'})}()
 c:=&vlessResponseConn{Conn:client}
 out:=make([]byte,2);_,err:=io.ReadFull(c,out)
 if err!=nil||string(out)!="ok"{t.Fatalf("response %q %v",out,err)}
}
func TestVLESSResponseReject(t *testing.T){
 client,server:=net.Pipe();defer client.Close();defer server.Close()
 go func(){_,_=server.Write([]byte{9,0,'x'})}()
 c:=&vlessResponseConn{Conn:client};buf:=make([]byte,5)
 if _,err:=c.Read(buf);err==nil{t.Fatal("accepted bad response")}
}
