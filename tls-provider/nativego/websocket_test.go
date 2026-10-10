package nativego

import (
 "bufio"
 "bytes"
 "context"
 "crypto/sha1"
 "encoding/base64"
 "errors"
 "io"
 "net"
 "net/http"
 "testing"
 "time"
)

func wsPeerUpgrade(c net.Conn)(*bufio.Reader,error){
 reader:=bufio.NewReader(c)
 request,err:=http.ReadRequest(reader)
 if err!=nil{return nil,err}
 defer request.Body.Close()
 if request.Method!="GET"||request.URL.Path!="/vpnpath"||request.Host!="cdn.example.com"{
  return nil,errors.New("wrong WebSocket upgrade target")
 }
 key:=request.Header.Get("Sec-WebSocket-Key")
 if key==""||request.Header.Get("Sec-WebSocket-Version")!="13"{return nil,errors.New("missing RFC6455 fields")}
 accept:=sha1.Sum([]byte(key+wsMagic))
 headers:="HTTP/1.1 101 Switching Protocols\r\n"+
  "Upgrade: websocket\r\n"+
  "Connection: Upgrade\r\n"+
  "Sec-WebSocket-Accept: "+base64.StdEncoding.EncodeToString(accept[:])+"\r\n\r\n"
 if err:=writeFull(c,[]byte(headers));err!=nil{return nil,err}
 return reader,nil
}

func TestWebSocketGoAuthenticatedMaskedTransport(t *testing.T){
 client,server:=net.Pipe()
 defer client.Close();defer server.Close()
 _=client.SetDeadline(time.Now().Add(5*time.Second));_=server.SetDeadline(time.Now().Add(5*time.Second))
 result:=make(chan error,1)
 go func(){
  r,err:=wsPeerUpgrade(server)
  if err!=nil{result<-err;return}
  var h [2]byte
  if _,err=io.ReadFull(r,h[:]);err!=nil{result<-err;return}
  if h[0]!=0x82||h[1]&0x80==0||h[1]&127!=4{result<-errors.New("unmasked/non-binary WS upload");return}
  var mask [4]byte
  if _,err=io.ReadFull(r,mask[:]);err!=nil{result<-err;return}
  payload:=make([]byte,4)
  if _,err=io.ReadFull(r,payload);err!=nil{result<-err;return}
  for i:=range payload{payload[i]^=mask[i%4]}
  if !bytes.Equal(payload,[]byte("ping")){result<-errors.New("invalid authenticated WS payload");return}
  // Two unmasked server fragments must be read as a continuous TCP stream.
  reply:=[]byte{0x02,2,'p','o',0x80,2,'n','g'}
  result<-writeFull(server,reply)
 }()
 n:=Node{ServerName:"example.com",Transport:"websocket",WSPath:"/vpnpath",WSHost:"cdn.example.com"}
 ws,err:=openWebSocket(context.Background(),client,n)
 if err!=nil{t.Fatal(err)}
 if _,err=ws.Write([]byte("ping"));err!=nil{t.Fatal(err)}
 reply:=make([]byte,4)
 if _,err=io.ReadFull(ws,reply);err!=nil{t.Fatal(err)}
 if string(reply)!="pong"{t.Fatalf("WebSocket relay returned %q",reply)}
 if err=<-result;err!=nil{t.Fatal(err)}
}

func TestWebSocketGoRejectsInvalidUpgrade(t *testing.T){
 client,server:=net.Pipe()
 defer client.Close();defer server.Close()
 _=client.SetDeadline(time.Now().Add(4*time.Second));_=server.SetDeadline(time.Now().Add(4*time.Second))
 go func(){
  _,_ = http.ReadRequest(bufio.NewReader(server))
  _=writeFull(server,[]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n"))
 }()
 _,err:=openWebSocket(context.Background(),client,Node{ServerName:"example.com",WSPath:"/"})
 if err==nil{t.Fatal("unverified WebSocket accept was admitted")}
}
func TestWebSocketGoRejectsMaskedServerFrame(t *testing.T){
 client,server:=net.Pipe()
 defer client.Close();defer server.Close()
 _=client.SetDeadline(time.Now().Add(4*time.Second));_=server.SetDeadline(time.Now().Add(4*time.Second))
 go func(){
  _,err:=wsPeerUpgrade(server)
  if err!=nil{return}
  _=writeFull(server,[]byte{0x82,0x80,0,0,0,0})
 }()
 conn,err:=openWebSocket(context.Background(),client,Node{ServerName:"example.com",WSPath:"/vpnpath",WSHost:"cdn.example.com"})
 if err!=nil{t.Fatal(err)}
 out:=make([]byte,4)
 if _,err=conn.Read(out);err==nil{t.Fatal("server-supplied masked WebSocket frame accepted")}
}

func TestWebSocketGoOriginalURI(t *testing.T){
 n,err:=ParseURI("vless://00112233-4455-6677-8899-aabbccddeeff@203.0.113.8:443?security=tls&sni=example.com&type=ws&host=cdn.example.com&path=%2Fvpnpath")
 if err!=nil{t.Fatal(err)}
 if n.Transport!="websocket"||n.WSPath!="/vpnpath"||n.WSHost!="cdn.example.com"{t.Fatalf("WebSocket URI options lost: %+v",n)}
 if _,err=NewDialer(n,func(context.Context,string,string)(net.Conn,error){return nil,errors.New("offline")});err!=nil{t.Fatal(err)}
 n.Security="reality"
 if _,err=NewDialer(n,func(context.Context,string,string)(net.Conn,error){return nil,errors.New("offline")});!errors.Is(err,ErrUnsupported){t.Fatalf("REALITY WebSocket must fail closed: %v",err)}
}
