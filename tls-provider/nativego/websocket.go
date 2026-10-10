package nativego

import (
 "bufio"
 "context"
 "crypto/rand"
 "crypto/sha1"
 "encoding/base64"
 "encoding/binary"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "strings"
 "sync"
 "time"
)

const wsMaxFrame = 1 << 20
const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func hasHeaderToken(raw,needle string)bool{
 for _,token:=range strings.Split(raw,","){
  if strings.EqualFold(strings.TrimSpace(token),needle){return true}
 }
 return false
}
func validWSHeader(v string)bool{
 return v!=""&&len(v)<2048&&!strings.ContainsAny(v,"\r\n\x00")
}
func openWebSocket(ctx context.Context,conn net.Conn,n Node)(net.Conn,error){
 path:=n.WSPath
 if path==""{path="/"}
 host:=n.WSHost
 if host==""{host=n.ServerName}
 if !strings.HasPrefix(path,"/")||!validWSHeader(path)||!validWSHeader(host){
  return nil,errors.New("nativego: invalid WebSocket path or host")
 }
 var key [16]byte
 if _,err:=rand.Read(key[:]);err!=nil{return nil,err}
 clientKey:=base64.StdEncoding.EncodeToString(key[:])
 handshake:="GET "+path+" HTTP/1.1\r\n"+
  "Host: "+host+"\r\n"+
  "Upgrade: websocket\r\n"+
  "Connection: Upgrade\r\n"+
  "Sec-WebSocket-Key: "+clientKey+"\r\n"+
  "Sec-WebSocket-Version: 13\r\n\r\n"
 deadline:=time.Now().Add(10*time.Second)
 if configured,ok:=ctx.Deadline();ok&&configured.Before(deadline){deadline=configured}
 _=conn.SetDeadline(deadline)
 if err:=writeFull(conn,[]byte(handshake));err!=nil{return nil,err}
 reader:=bufio.NewReaderSize(conn,4096)
 response,err:=http.ReadResponse(reader,&http.Request{Method:http.MethodGet})
 if err!=nil{return nil,err}
 defer response.Body.Close()
 hash:=sha1.Sum([]byte(clientKey+wsMagic))
 want:=base64.StdEncoding.EncodeToString(hash[:])
 if response.StatusCode!=http.StatusSwitchingProtocols||
  !hasHeaderToken(response.Header.Get("Upgrade"),"websocket")||
  !hasHeaderToken(response.Header.Get("Connection"),"upgrade")||
  response.Header.Get("Sec-WebSocket-Accept")!=want||
  response.Header.Get("Sec-WebSocket-Extensions")!=""{
  return nil,fmt.Errorf("nativego: WebSocket upgrade authentication rejected (status %d)",response.StatusCode)
 }
 _=conn.SetDeadline(time.Time{})
 return &websocketConn{Conn:conn,reader:reader},nil
}

type websocketConn struct{
 net.Conn
 reader *bufio.Reader
 readMu sync.Mutex
 writeMu sync.Mutex
 pending []byte
 fragmenting bool
}

func(w *websocketConn)writeFrame(opcode byte,payload []byte)error{
 if len(payload)>wsMaxFrame{return errors.New("nativego: WebSocket outbound frame too large")}
 frame:=make([]byte,0,len(payload)+14)
 frame=append(frame,0x80|opcode)
 n:=len(payload)
 if n<126{frame=append(frame,0x80|byte(n))}else if n<=65535{
  frame=append(frame,0x80|126,byte(n>>8),byte(n))
 }else{
  frame=append(frame,0x80|127)
  var extent [8]byte;binary.BigEndian.PutUint64(extent[:],uint64(n))
  frame=append(frame,extent[:]...)
 }
 var mask [4]byte
 if _,err:=rand.Read(mask[:]);err!=nil{return err}
 frame=append(frame,mask[:]...)
 for i,p:=range payload{frame=append(frame,p^mask[i%4])}
 return writeFull(w.Conn,frame)
}
func(w *websocketConn)Write(p []byte)(int,error){
 w.writeMu.Lock();defer w.writeMu.Unlock()
 sent:=0
 for sent<len(p){
  size:=len(p)-sent
  if size>32768{size=32768}
  if err:=w.writeFrame(2,p[sent:sent+size]);err!=nil{return sent,err}
  sent+=size
 }
 return sent,nil
}
func(w *websocketConn)Read(out []byte)(int,error){
 if len(out)==0{return 0,nil}
 w.readMu.Lock();defer w.readMu.Unlock()
 for{
  if len(w.pending)>0{
   n:=copy(out,w.pending)
   w.pending=w.pending[n:]
   return n,nil
  }
  var header [2]byte
  if _,err:=io.ReadFull(w.reader,header[:]);err!=nil{return 0,err}
  if header[0]&0x70!=0||header[1]&0x80!=0{
   return 0,errors.New("nativego: WebSocket server frame RSV/mask violation")
  }
  opcode:=header[0]&0x0f
  fin:=header[0]&0x80!=0
  size:=uint64(header[1]&0x7f)
  if size==126{
   var extra [2]byte
   if _,err:=io.ReadFull(w.reader,extra[:]);err!=nil{return 0,err}
   size=uint64(binary.BigEndian.Uint16(extra[:]))
   if size<126{return 0,errors.New("nativego: nonminimal WebSocket frame length")}
  }else if size==127{
   var extra [8]byte
   if _,err:=io.ReadFull(w.reader,extra[:]);err!=nil{return 0,err}
   size=binary.BigEndian.Uint64(extra[:])
   if size<=65535{return 0,errors.New("nativego: nonminimal WebSocket frame length")}
  }
  if size>wsMaxFrame{return 0,errors.New("nativego: inbound WebSocket frame limit")}
  if opcode>=8&&(size>125||!fin){return 0,errors.New("nativego: invalid WebSocket control frame")}
  payload:=make([]byte,int(size))
  if _,err:=io.ReadFull(w.reader,payload);err!=nil{return 0,err}
  switch opcode{
  case 2:
   if w.fragmenting{return 0,errors.New("nativego: nested WebSocket binary frame")}
   w.fragmenting=!fin
  case 0:
   if !w.fragmenting{return 0,errors.New("nativego: stray WebSocket continuation")}
   w.fragmenting=!fin
  case 8:
   return 0,io.EOF
  case 9:
   w.writeMu.Lock();err:=w.writeFrame(10,payload);w.writeMu.Unlock()
   if err!=nil{return 0,err}
   continue
  case 10:
   continue
  default:
   return 0,errors.New("nativego: unsupported WebSocket message type")
  }
  if len(payload)==0{continue}
  n:=copy(out,payload)
  if n<len(payload){w.pending=payload[n:]}
  return n,nil
 }
}
func(w *websocketConn)CloseWrite()error{
 if cw,ok:=w.Conn.(interface{CloseWrite()error});ok{return cw.CloseWrite()}
 return nil
}
