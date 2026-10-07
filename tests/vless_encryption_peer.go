// Independent peer: no core code or external proxy engine is linked.
package main
import (
 "bytes"
 "crypto/aes"
 "crypto/cipher"
 "crypto/ecdh"
 "crypto/mlkem"
 "crypto/rand"
 "crypto/sha256"
 "crypto/tls"
 "encoding/base64"
 "encoding/binary"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "net"
 "os"
 "sync"
 "time"
 "lukechampine.com/blake3"
)
type aead struct{cipher.AEAD;count uint64}
func derived(context,key []byte)[]byte{b:=make([]byte,32);blake3.DeriveKey(b,string(context),key);return b}
func newAead(context,key []byte)*aead{block,_:=aes.NewCipher(derived(context,key));c,_:=cipher.NewGCM(block);return &aead{AEAD:c}}
func(a *aead)nonce()[]byte{a.count++;b:=make([]byte,12);binary.BigEndian.PutUint64(b[4:],a.count);return b}
func(a *aead)decrypt(b,aad []byte)([]byte,error){return a.Open(nil,a.nonce(),b,aad)}
func(a *aead)encrypt(b,aad []byte)[]byte{return a.Seal(nil,a.nonce(),b,aad)}
func ctr(key,iv []byte)cipher.Stream{block,_:=aes.NewCipher(derived([]byte("VLESS"),key));return cipher.NewCTR(block,iv)}
func read(r io.Reader,n int)([]byte,error){b:=make([]byte,n);_,err:=io.ReadFull(r,b);return b,err}
type key struct{x *ecdh.PrivateKey;kem *mlkem.DecapsulationKey768;public []byte}
type ticket struct{pfs []byte;seen map[[32]byte]bool}
type peer struct{keys []key;mode,bad,target string;mu sync.Mutex;tickets map[string]*ticket;resumes int}
type stream struct{net.Conn;readCipher,writeCipher *aead;inCTR,outCTR cipher.Stream;buffer []byte;bad string;badSent bool;mu sync.Mutex}
func(s *stream)Read(b []byte)(int,error){if len(s.buffer)==0{header,err:=read(s.Conn,5);if err!=nil{return 0,err};if s.inCTR!=nil{s.inCTR.XORKeyStream(header,header)};n:=int(binary.BigEndian.Uint16(header[3:]));if header[0]!=23||!bytes.Equal(header[1:3],[]byte{3,3})||n<17||n>16640{return 0,fmt.Errorf("record header")};data,err:=read(s.Conn,n);if err!=nil{return 0,err};s.buffer,err=s.readCipher.decrypt(data,header);if err!=nil{return 0,err}};n:=copy(b,s.buffer);s.buffer=s.buffer[n:];return n,nil}
func(s *stream)Write(b []byte)(int,error){s.mu.Lock();defer s.mu.Unlock();for pos:=0;pos<len(b);{n:=min(10001,len(b)-pos);header:=[]byte{23,3,3,byte((n+16)>>8),byte(n+16)};payload:=s.writeCipher.encrypt(b[pos:pos+n],header);if s.bad!=""&&!s.badSent{if s.bad=="record_tag"{payload[len(payload)-1]^=1};if s.bad=="record_length"{header[0]=22};s.badSent=true};if s.outCTR!=nil{s.outCTR.XORKeyStream(header,header)};_,err:=s.Conn.Write(append(header,payload...));if err!=nil{return pos,err};pos+=n};return len(b),nil}
func(p *peer)handshake(c net.Conn)(*stream,error){
 iv,err:=read(c,16);if err!=nil{return nil,err};var nfs []byte;var mask cipher.Stream
 for i,k:=range p.keys{n:=32;if k.kem!=nil{n=1088};pub,e:=read(c,n);if e!=nil{return nil,e};if mask!=nil{mask.XORKeyStream(pub[:32],pub[:32])};if p.mode!="native"{ctr(k.public,iv).XORKeyStream(pub,pub)}
  if k.x!=nil{if pub[31]>127{return nil,fmt.Errorf("noncanonical X25519")};pk,e:=ecdh.X25519().NewPublicKey(pub);if e!=nil{return nil,e};nfs,e=k.x.ECDH(pk);if e!=nil{return nil,e}}else{nfs,e=k.kem.Decapsulate(pub);if e!=nil{return nil,e}}
  if i+1<len(p.keys){tag,e:=read(c,32);if e!=nil{return nil,e};mask=ctr(nfs,iv);mask.XORKeyStream(tag,tag);expected:=blake3.Sum256(p.keys[i+1].public);if !bytes.Equal(tag,expected[:]){return nil,fmt.Errorf("relay commitment")}}
 }
 auth:=newAead(iv,nfs);encLength,err:=read(c,18);if err!=nil{return nil,err};length,err:=auth.decrypt(encLength,nil);if err!=nil{return nil,err};n:=int(binary.BigEndian.Uint16(length));s:=&stream{Conn:c,bad:p.bad}
 if n==32{
  encrypted,err:=read(c,32);if err!=nil{return nil,err};id,err:=auth.decrypt(encrypted,nil);if err!=nil{return nil,err};p.mu.Lock();saved:=p.tickets[string(id)];digest:=sha256.Sum256(nfs);if saved==nil||saved.seen[digest]{p.mu.Unlock();return nil,fmt.Errorf("invalid/replayed ticket")};saved.seen[digest]=true;p.resumes++;p.mu.Unlock();fmt.Fprintln(os.Stderr,"RESUMED")
  united:=append(append([]byte(nil),saved.pfs...),nfs...);response:=make([]byte,16);_,_=rand.Read(response);if _,err=c.Write(response);err!=nil{return nil,err};s.readCipher=newAead(encrypted,united);s.writeCipher=newAead(response,united);if p.mode=="random"{s.inCTR=ctr(united,iv);s.outCTR=ctr(united,response)};return s,nil
 }
 if n!=1232{return nil,fmt.Errorf("hybrid offer length")};encPublic,err:=read(c,n);if err!=nil{return nil,err};public,err:=auth.decrypt(encPublic,nil);if err!=nil{return nil,err};kem,err:=mlkem.NewEncapsulationKey768(public[:1184]);if err!=nil{return nil,err};kemKey,kemCipher:=kem.Encapsulate();x,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{return nil,err};pk,err:=ecdh.X25519().NewPublicKey(public[1184:]);if err!=nil{return nil,err};xKey,err:=x.ECDH(pk);if err!=nil{return nil,err};pfs:=append(kemKey,xKey...);united:=append(append([]byte(nil),pfs...),nfs...);serverPublic:=append(kemCipher,x.PublicKey().Bytes()...)
 s.readCipher=newAead(public,united);s.writeCipher=newAead(serverPublic,united)
 maxNonce:=bytes.Repeat([]byte{255},12);reply:=auth.Seal(nil,maxNonce,serverPublic,nil);if p.bad=="handshake_tag"{reply[len(reply)-1]^=1}
 id:=make([]byte,16);_,_=rand.Read(id);binary.BigEndian.PutUint16(id,600);p.mu.Lock();p.tickets[string(id)]=&ticket{pfs:append([]byte(nil),pfs...),seen:map[[32]byte]bool{}};p.mu.Unlock()
 ticketWire:=s.writeCipher.encrypt(id,nil);if p.bad=="ticket_tag"{ticketWire[len(ticketWire)-1]^=1};reply=append(reply,ticketWire...)
 pad:=make([]byte,187);lengthWire:=s.writeCipher.encrypt([]byte{0,byte(len(pad)+16)},nil);padWire:=s.writeCipher.encrypt(pad,nil)
 if p.bad=="padding_tag"{padWire[len(padWire)-1]^=1};reply=append(reply,lengthWire...);reply=append(reply,padWire...)
 for start:=0;start<len(reply);{n:=min(79,len(reply)-start);if _,err=c.Write(reply[start:start+n]);err!=nil{return nil,err};start+=n}
 encLength,err=read(c,18);if err!=nil{return nil,err};length,err=auth.decrypt(encLength,nil);if err!=nil{return nil,err};n=int(binary.BigEndian.Uint16(length));if n<16||n>65535{return nil,fmt.Errorf("client padding length")};padWire,err=read(c,n);if err!=nil{return nil,err};if _,err=auth.decrypt(padWire,nil);err!=nil{return nil,err}
 if p.mode=="random"{s.inCTR=ctr(united,iv);s.outCTR=ctr(united,id)};return s,nil
}
func(p *peer)handle(raw net.Conn){defer raw.Close();_=raw.SetDeadline(time.Now().Add(15*time.Second));s,err:=p.handshake(raw);if err!=nil{if p.bad==""{fmt.Fprintln(os.Stderr,"VALIDATION:",err)};return};defer s.Close();conn,err:=net.DialTimeout("tcp",p.target,3*time.Second);if err!=nil{return};defer conn.Close();go func(){_,_=io.Copy(conn,s)}();_,_=io.Copy(s,conn)}
func main(){target:=flag.String("target","","Python oracle");mode:=flag.String("mode","native","wire mode");relays:=flag.Int("relays",1,"static relay keys");kemLast:=flag.Bool("kem",false,"static ML-KEM key");bad:=flag.String("bad","","negative fixture");cert:=flag.String("cert","","TLS certificate");private:=flag.String("key","","TLS key");flag.Parse();p:=&peer{mode:*mode,target:*target,bad:*bad,tickets:map[string]*ticket{}};public:=[]string{}
 for i:=0;i<*relays;i++{k:=key{};if *kemLast&&i==*relays-1{k.kem,_=mlkem.GenerateKey768();k.public=k.kem.EncapsulationKey().Bytes()}else{k.x,_=ecdh.X25519().GenerateKey(rand.Reader);k.public=k.x.PublicKey().Bytes()};p.keys=append(p.keys,k);public=append(public,base64.RawURLEncoding.EncodeToString(k.public))}
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{panic(err)};port:=listener.Addr().(*net.TCPAddr).Port;if *cert!=""{certificate,err:=tls.LoadX509KeyPair(*cert,*private);if err!=nil{panic(err)};listener=tls.NewListener(listener,&tls.Config{Certificates:[]tls.Certificate{certificate},MinVersion:tls.VersionTLS13})};b,_:=json.Marshal(map[string]any{"port":port,"keys":public});fmt.Println(string(b));for{conn,err:=listener.Accept();if err!=nil{return};go p.handle(conn)}}
