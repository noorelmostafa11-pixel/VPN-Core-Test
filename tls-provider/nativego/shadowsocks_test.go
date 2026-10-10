package nativego

import (
 "bytes"
 "context"
 "crypto/rand"
 "errors"
 "io"
 "net"
 "net/netip"
 "testing"
 "time"
)

func TestClassicShadowsocksAEADProtectedPeer(t *testing.T){
 methods:=[]string{"aes-128-gcm","aes-192-gcm","aes-256-gcm","chacha20-ietf-poly1305"}
 for _,method:=range methods{
  t.Run(method,func(t *testing.T){
   a,b:=net.Pipe()
   defer a.Close();defer b.Close()
   _=a.SetDeadline(time.Now().Add(5*time.Second))
   _=b.SetDeadline(time.Now().Add(5*time.Second))
   result:=make(chan error,1)
   go func(){
    peer:=&ssStreamConn{Conn:b,method:method,master:ssMaster("strong-test-password",ssAEADKeySize(method))}
    target:=[]byte{1,1,2,3,4,1,187}
    buf:=make([]byte,len(target))
    if _,err:=io.ReadFull(peer,buf);err!=nil{result<-err;return}
    if !bytes.Equal(buf,target){result<-errors.New("Shadowsocks target mismatch");return}
    message:=make([]byte,4)
    if _,err:=io.ReadFull(peer,message);err!=nil{result<-err;return}
    if string(message)!="ping"{result<-errors.New("Shadowsocks payload mismatch");return}
    salt:=make([]byte,ssAEADKeySize(method))
    if _,err:=rand.Read(salt);err!=nil{result<-err;return}
    out,err:=ssCipher(method,peer.master,salt)
    if err!=nil{result<-err;return}
    if err=writeFull(b,salt);err!=nil{result<-err;return}
    peer.outbound=out
    result<-peer.writeFrame([]byte("pong"))
   }()
   protected:=func(ctx context.Context,network,address string)(net.Conn,error){
    if network!="tcp"||address!="203.0.113.8:8388"{return nil,errors.New("unprotected or wrong node socket")}
    return a,nil
   }
   node:=Node{Protocol:"ss",Address:"203.0.113.8",Port:8388,Security:"none",Transport:"raw",Cipher:method,Password:"strong-test-password"}
   dialer,err:=NewDialer(node,protected)
   if err!=nil{t.Fatal(err)}
   conn,err:=dialer.DialStream(context.Background(),netip.MustParseAddrPort("1.2.3.4:443"))
   if err!=nil{t.Fatal(err)}
   defer conn.Close()
   if _,err=conn.Write([]byte("ping"));err!=nil{t.Fatal(err)}
   answer:=make([]byte,4)
   if _,err=io.ReadFull(conn,answer);err!=nil{t.Fatal(err)}
   if string(answer)!="pong"{t.Fatalf("Shadowsocks response %q",answer)}
   if err=<-result;err!=nil{t.Fatal(err)}
  })
 }
}

func TestShadowsocksAEADRejectedPlaintextAndDowngrades(t *testing.T){
 protect:=func(context.Context,string,string)(net.Conn,error){t.Fatal("SS must not connect");return nil,nil}
 base:=Node{Protocol:"ss",Address:"203.0.113.1",Port:8388,Security:"none",Transport:"raw",Cipher:"aes-256-gcm",Password:"password"}
 cases:=[]Node{}
 x:=base;x.Security="tls";cases=append(cases,x)
 x=base;x.Cipher="none";cases=append(cases,x)
 x=base;x.Cipher="aes-256-cfb";cases=append(cases,x)
 x=base;x.Cipher="2022-blake3-aes-256-gcm";cases=append(cases,x)
 x=base;x.Transport="websocket";cases=append(cases,x)
 for _,c:=range cases{
  if _,err:=NewDialer(c,protect);!errors.Is(err,ErrUnsupported){t.Fatalf("unsupported SS must fail closed: %+v %v",c,err)}
 }
}

func TestShadowsocksAEADTamperedRecordRejected(t *testing.T){
 method:="aes-256-gcm"
 secret:="password"
 master:=ssMaster(secret,32)
 salt:=make([]byte,32);if _,err:=rand.Read(salt);err!=nil{t.Fatal(err)}
 aead,err:=ssCipher(method,master,salt);if err!=nil{t.Fatal(err)}
 var nonce [12]byte
 length:=aead.Seal(nil,nonce[:],[]byte{0,4},nil)
 if err=ssAdvance(&nonce);err!=nil{t.Fatal(err)}
 bad:=aead.Seal(nil,nonce[:],[]byte("pong"),nil)
 bad[len(bad)-1]^=1
 a,b:=net.Pipe();defer a.Close();defer b.Close()
 go func(){_ = writeFull(b,append(append(append([]byte(nil),salt...),length...),bad...))}()
 stream:=&ssStreamConn{Conn:a,method:method,master:master}
 buf:=make([]byte,32)
 if _,err=stream.Read(buf);err==nil{t.Fatal("accepted tampered Shadowsocks AEAD body")}
}

func TestShadowsocksClassicURI(t *testing.T){
 // SIP002 base64url userinfo for aes-256-gcm:test-password
 uri:="ss://YWVzLTI1Ni1nY206dGVzdC1wYXNzd29yZA@198.51.100.9:8388#original-node"
 n,err:=ParseURI(uri)
 if err!=nil{t.Fatal(err)}
 if n.Protocol!="ss"||n.Security!="none"||n.Cipher!="aes-256-gcm"||n.Password!="test-password"||n.Address!="198.51.100.9"{t.Fatalf("invalid original Shadowsocks URI decode %+v",n)}
 d,err:=NewDialer(n,func(context.Context,string,string)(net.Conn,error){return nil,errors.New("offline test")})
 if err!=nil||d==nil{t.Fatalf("valid SS URI was rejected: %v",err)}
}
