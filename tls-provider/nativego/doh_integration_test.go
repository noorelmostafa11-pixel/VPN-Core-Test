package nativego

import (
 "bufio"
 "bytes"
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "errors"
 "fmt"
 "io"
 "math/big"
 "net"
 "os"
 "os/exec"
 "runtime"
 "testing"
 "net/http"
 "time"
)

// Verify DNS-over-HTTPS is NOT sent around the selected VPN node:
// outer pinned TLS + VLESS target 1.1.1.1:443 + independently certificate-
// authenticated inner DoH TLS + full HTTP DNS-message answer. Local TLS peers
// are controlled; this does not claim real public Internet DNS access.
func TestNativeGoAuthenticatedDNSOverVLESS(t *testing.T){
 if runtime.GOOS=="windows"{t.Skip("controlled temporary CA trust validated on Linux")}
 if os.Getenv("VPN_NATIVE_GO_DOH_CHILD")!="1"{
  cmd:=exec.Command(os.Args[0],"-test.run=^TestNativeGoAuthenticatedDNSOverVLESS$","-test.v")
  cmd.Env=append(os.Environ(),"VPN_NATIVE_GO_DOH_CHILD=1")
  out,err:=cmd.CombinedOutput()
  if err!=nil{t.Fatalf("authenticated nested DNS over VLESS: %v\n%s",err,out)}
  return
 }
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 template:=&x509.Certificate{
  SerialNumber:big.NewInt(993),Subject:pkix.Name{CommonName:"example.com"},
  DNSNames:[]string{"example.com","cloudflare-dns.com"},
  NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),
  IsCA:true,BasicConstraintsValid:true,
  KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
 }
 der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key)
 if err!=nil{t.Fatal(err)}
 caPath:=t.TempDir()+"/nativego-doh-test.pem"
 if err=os.WriteFile(caPath,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);err!=nil{t.Fatal(err)}
 t.Setenv("SSL_CERT_FILE",caPath)
 cert:=tls.Certificate{Certificate:[][]byte{der},PrivateKey:key}
 peerTLS:=&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS12}
 listener,err:=tls.Listen("tcp","127.0.0.1:0",peerTLS);if err!=nil{t.Fatal(err)}
 defer listener.Close()
 peerErr:=make(chan error,1)
 go func(){
  outer,err:=listener.Accept();if err!=nil{peerErr<-err;return}
  defer outer.Close()
  _=outer.SetDeadline(time.Now().Add(10*time.Second))
  header:=make([]byte,26)
  if _,err=io.ReadFull(outer,header);err!=nil{peerErr<-err;return}
  if header[0]!=0||header[18]!=1||header[19]!=1||header[20]!=187||header[21]!=1||
   !bytes.Equal(header[22:26],[]byte{1,1,1,1}){
   peerErr<-errors.New("VLESS did not route DNS through owned encrypted proxy target");return
  }
  if err=writeFull(outer,[]byte{0,0});err!=nil{peerErr<-err;return}
  inner:=tls.Server(outer,peerTLS)
  if err=inner.Handshake();err!=nil{peerErr<-fmt.Errorf("inner DoH TLS handshake: %w",err);return}
  req,err:=httpReadDNSRequest(inner)
  if err!=nil{peerErr<-err;return}
  if len(req)<12{peerErr<-errors.New("DNS query missing");return}
  reply:=append([]byte(nil),req...)
  reply[2],reply[3]=0x81,0x80
  headers:=fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",len(reply))
  if err=writeFull(inner,[]byte(headers));err!=nil{peerErr<-err;return}
  peerErr<-writeFull(inner,reply)
 }()
 node:=Node{Protocol:"vless",Address:"203.0.113.9",Port:443,ServerName:"example.com",Security:"tls",Transport:"raw",UUID:"00112233-4455-6677-8899-aabbccddeeff"}
 protected:=func(ctx context.Context,network,address string)(net.Conn,error){
  if network!="tcp"||address!="203.0.113.9:443"{return nil,errors.New("unapproved physical DNS fallback")}
  return (&net.Dialer{Timeout:4*time.Second}).DialContext(ctx,network,listener.Addr().String())
 }
 dialer,err:=NewDialer(node,protected);if err!=nil{t.Fatal(err)}
 query:=[]byte{0xf1,0x0a,1,0,0,1,0,0,0,0,0,0,1,'a',3,'c','o','m',0,0,1,0,1}
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
 reply,err:=NewDoH(dialer).Resolve(ctx,query)
 if err!=nil{t.Fatal(err)}
 if len(reply)!=len(query)||reply[0]!=0xf1||reply[1]!=0x0a||reply[2]&0x80==0{
  t.Fatalf("authenticated DNS reply invalid: %x",reply)
 }
 select{
 case err=<-peerErr:if err!=nil{t.Fatal(err)}
 case <-time.After(8*time.Second):t.Fatal("controlled DoH peer failed to complete")
 }
}

// The controlled server parses exactly one standard DoH HTTP request.
// Parsing is intentionally bounded and uses net/http, not a second proxy stack.
func httpReadDNSRequest(c net.Conn)([]byte,error){
 r,err:=http.ReadRequest(bufio.NewReader(c))
 if err!=nil{return nil,err}
 defer r.Body.Close()
 if r.Method!="POST"||r.URL.Path!="/dns-query"||
  r.Header.Get("Content-Type")!="application/dns-message"||
  r.Host!="cloudflare-dns.com" {
  return nil,errors.New("unexpected DoH endpoint or content type")
 }
 body,err:=io.ReadAll(io.LimitReader(r.Body,65536))
 if err!=nil{return nil,err}
 return body,nil
}
