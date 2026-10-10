package nativego

// Classic Shadowsocks AEAD TCP, implemented in Go without CGO. Deliberately
// supports only standard AES-GCM and IETF ChaCha20-Poly1305 variants: all
// legacy stream/no-auth/2022 features must fail closed until separately tested.

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/md5"
 "crypto/rand"
 "crypto/sha1"
 "errors"
 "fmt"
 "io"
 "net"
 "net/netip"
 "sync"

 "golang.org/x/crypto/chacha20poly1305"
 "golang.org/x/crypto/hkdf"
)

func ssAEADKeySize(method string)int{
 switch method{
 case "aes-128-gcm":return 16
 case "aes-192-gcm":return 24
 case "aes-256-gcm","chacha20-ietf-poly1305":return 32
 default:return 0
 }
}

// EVP_BytesToKey-compatible MD5 expansion for the classic Shadowsocks AEAD
// password-derived master key, matching the original C++ core.
func ssMaster(password string,size int)[]byte{
 key:=make([]byte,0,size)
 var last []byte
 for len(key)<size{
  block:=append(append([]byte(nil),last...),[]byte(password)...)
  digest:=md5.Sum(block)
  last=append([]byte(nil),digest[:]...)
  key=append(key,last...)
 }
 return key[:size]
}
func ssCipher(method string,master,salt []byte)(cipher.AEAD,error){
 size:=ssAEADKeySize(method)
 if size==0||len(master)!=size||len(salt)!=size{return nil,ErrUnsupported}
 key:=make([]byte,size)
 if _,err:=io.ReadFull(hkdf.New(sha1.New,master,salt,[]byte("ss-subkey")),key);err!=nil{return nil,err}
 if method=="chacha20-ietf-poly1305"{return chacha20poly1305.New(key)}
 block,err:=aes.NewCipher(key)
 if err!=nil{return nil,err}
 return cipher.NewGCM(block)
}
func ssAdvance(nonce *[12]byte)error{
 for i:=0;i<len(nonce);i++{
  nonce[i]++
  if nonce[i]!=0{return nil}
 }
 return errors.New("nativego: Shadowsocks AEAD nonce exhausted")
}

// ssStreamConn preserves independent read and write AEAD keys and nonce
// sequences, never logs credentials, and never exposes unauthenticated bytes.
type ssStreamConn struct{
 net.Conn
 method string
 master []byte
 writeMu sync.Mutex
 readMu sync.Mutex
 outbound cipher.AEAD
 inbound cipher.AEAD
 outNonce [12]byte
 inNonce [12]byte
 receive []byte
}

func newSSStreamConn(c net.Conn,method,password string)(*ssStreamConn,error){
 size:=ssAEADKeySize(method)
 if size==0||password==""{return nil,ErrUnsupported}
 master:=ssMaster(password,size)
 salt:=make([]byte,size)
 if _,err:=rand.Read(salt);err!=nil{return nil,err}
 aead,err:=ssCipher(method,master,salt)
 if err!=nil{return nil,err}
 if err=writeFull(c,salt);err!=nil{return nil,err}
 return &ssStreamConn{Conn:c,method:method,master:master,outbound:aead},nil
}

func(s *ssStreamConn)writeFrame(plain []byte)error{
 if len(plain)>0x3fff{return errors.New("nativego: Shadowsocks AEAD frame too large")}
 var size [2]byte
 size[0],size[1]=byte(len(plain)>>8),byte(len(plain))
 length:=s.outbound.Seal(nil,s.outNonce[:],size[:],nil)
 if err:=ssAdvance(&s.outNonce);err!=nil{return err}
 body:=s.outbound.Seal(nil,s.outNonce[:],plain,nil)
 if err:=ssAdvance(&s.outNonce);err!=nil{return err}
 frame:=make([]byte,0,len(length)+len(body))
 frame=append(frame,length...)
 frame=append(frame,body...)
 return writeFull(s.Conn,frame)
}
func(s *ssStreamConn)Write(plain []byte)(int,error){
 s.writeMu.Lock()
 defer s.writeMu.Unlock()
 sent:=0
 for sent<len(plain){
  chunk:=len(plain)-sent
  if chunk>0x3fff{chunk=0x3fff}
  if err:=s.writeFrame(plain[sent:sent+chunk]);err!=nil{return sent,err}
  sent+=chunk
 }
 return sent,nil
}
func(s *ssStreamConn)Read(out []byte)(int,error){
 if len(out)==0{return 0,nil}
 s.readMu.Lock()
 defer s.readMu.Unlock()
 if len(s.receive)>0{
  n:=copy(out,s.receive)
  s.receive=s.receive[n:]
  return n,nil
 }
 if s.inbound==nil{
  salt:=make([]byte,len(s.master))
  if _,err:=io.ReadFull(s.Conn,salt);err!=nil{return 0,err}
  cipher,err:=ssCipher(s.method,s.master,salt)
  if err!=nil{return 0,err}
  s.inbound=cipher
 }
 overhead:=s.inbound.Overhead()
 length:=make([]byte,2+overhead)
 if _,err:=io.ReadFull(s.Conn,length);err!=nil{return 0,err}
 sizeBytes,err:=s.inbound.Open(nil,s.inNonce[:],length,nil)
 if err!=nil{return 0,fmt.Errorf("nativego: Shadowsocks AEAD length authentication failed: %w",err)}
 if err=ssAdvance(&s.inNonce);err!=nil{return 0,err}
 count:=int(sizeBytes[0])<<8|int(sizeBytes[1])
 if count>0x3fff{return 0,errors.New("nativego: Shadowsocks AEAD frame length out of range")}
 encrypted:=make([]byte,count+overhead)
 if _,err=io.ReadFull(s.Conn,encrypted);err!=nil{return 0,err}
 plain,err:=s.inbound.Open(nil,s.inNonce[:],encrypted,nil)
 if err!=nil{return 0,fmt.Errorf("nativego: Shadowsocks AEAD body authentication failed: %w",err)}
 if err=ssAdvance(&s.inNonce);err!=nil{return 0,err}
 n:=copy(out,plain)
 s.receive=append(s.receive[:0],plain[n:]...)
 return n,nil
}
func(s *ssStreamConn)CloseWrite()error{
 if cw,ok:=s.Conn.(interface{CloseWrite()error});ok{return cw.CloseWrite()}
 // TCP half-close isn't available on every authenticated stream wrapper.
 // Return nil without closing a connection that still holds unread replies.
 return nil
}

// ProtectedClassicSSStream creates a single protected and authenticated
// Shadowsocks AEAD TCP tunnel. No raw/plaintext fallback is available.
func(d *Dialer)dialShadowsocksStream(ctx context.Context,target netip.AddrPort)(net.Conn,error){
 if d==nil||d.protected==nil{return nil,ErrUnprotected}
 address:=net.JoinHostPort(d.node.Address,fmt.Sprint(d.node.Port))
 raw,err:=d.protected(ctx,"tcp",address)
 if err!=nil{return nil,fmt.Errorf("nativego: protected SS connect: %w",err)}
 c,err:=newSSStreamConn(raw,d.node.Cipher,d.node.Password)
 if err!=nil{_=raw.Close();return nil,err}
 // Classic SS uses SOCKS address ordering ATYP + ADDR + PORT, matching
 // the original project Protocol::open() destination serialization.
 destination:=destinationBytes(target)
 header:=make([]byte,0,len(destination))
 header=append(header,destination[2])
 header=append(header,destination[3:]...)
 header=append(header,destination[:2]...)
 if _,err=c.Write(header);err!=nil{_=c.Close();return nil,err}
 return c,nil
}
