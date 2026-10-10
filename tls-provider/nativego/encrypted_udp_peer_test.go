package nativego

import (
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
 "net/netip"
 "os"
 "os/exec"
 "runtime"
 "testing"
 "time"
)

// Real, certificate-verified TLS peers with raw VLESS and Trojan UDP frames.
// This is controlled-protocol evidence, not public Internet acceptance.
func TestNativeGoEncryptedUDPPeer(t *testing.T) {
 if runtime.GOOS=="windows"{t.Skip("temporary CA via SSL_CERT_FILE is Linux-only")}
 if os.Getenv("VPN_NATIVE_GO_UDP_CHILD")!="1" {
  cmd:=exec.Command(os.Args[0],"-test.run=^TestNativeGoEncryptedUDPPeer$","-test.v")
  cmd.Env=append(os.Environ(),"VPN_NATIVE_GO_UDP_CHILD=1")
  output,err:=cmd.CombinedOutput()
  if err!=nil{t.Fatalf("protected encrypted UDP test: %v\n%s",err,output)}
  return
 }
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
 if err!=nil{t.Fatal(err)}
 crt:=&x509.Certificate{
  SerialNumber:big.NewInt(2001),
  Subject:pkix.Name{CommonName:"example.com"},
  DNSNames:[]string{"example.com"},
  NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),
  KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
  IsCA:true,BasicConstraintsValid:true,
 }
 der,err:=x509.CreateCertificate(rand.Reader,crt,crt,&key.PublicKey,key)
 if err!=nil{t.Fatal(err)}
 cert:=tls.Certificate{Certificate:[][]byte{der},PrivateKey:key}
 ca:=t.TempDir()+"/trusted-go-udp.pem"
 if err=os.WriteFile(ca,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);err!=nil{t.Fatal(err)}
 t.Setenv("SSL_CERT_FILE",ca)
 target:=netip.MustParseAddrPort("1.2.3.4:53")
 for _,protocol:=range []string{"vless","trojan"} {
  t.Run(protocol,func(t *testing.T) {
   ln,err:=tls.Listen("tcp","127.0.0.1:0",&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS12})
   if err!=nil{t.Fatal(err)}
   defer ln.Close()
   peerErr:=make(chan error,1)
   go func(){
    c,e:=ln.Accept()
    if e!=nil{peerErr<-e;return}
    defer c.Close()
    _=c.SetDeadline(time.Now().Add(5*time.Second))
    headerSize,cmdByte:=26,byte(2)
    if protocol=="trojan"{headerSize,cmdByte=68,3}
    header:=make([]byte,headerSize)
    if _,e=io.ReadFull(c,header);e!=nil{peerErr<-e;return}
    index:=18
    if protocol=="trojan"{index=58}
    if header[index]!=cmdByte{peerErr<-fmt.Errorf("incorrect encrypted UDP command %x",header);return}
    want:=[]byte("ping")
    var in []byte
    if protocol=="vless" {
     in=make([]byte,2+len(want))
    } else {in=make([]byte,11+len(want))}
    if _,e=io.ReadFull(c,in);e!=nil{peerErr<-e;return}
    if !bytes.Equal(in[len(in)-len(want):],want){peerErr<-fmt.Errorf("incorrect UDP request: %x",in);return}
    var reply []byte
    if protocol=="vless" {reply=[]byte{0,0,0,4,'p','o','n','g'}} else {
     reply=[]byte{1,1,2,3,4,0,53,0,4,'\r','\n','p','o','n','g'}
    }
    peerErr<-writeFull(c,reply)
   }()
   node:=Node{Protocol:protocol,Address:"203.0.113.8",Port:443,ServerName:"example.com",Security:"tls",Transport:"raw",UUID:"00112233-4455-6677-8899-aabbccddeeff",Password:"test-password"}
   protected:=func(ctx context.Context,network,address string)(net.Conn,error) {
    if network!="tcp"||address!="203.0.113.8:443"{return nil,errors.New("unprotected or unexpected external address")}
    return (&net.Dialer{}).DialContext(ctx,network,ln.Addr().String())
   }
   d,e:=NewDialer(node,protected)
   if e!=nil{t.Fatal(e)}
   ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
   defer cancel()
   session,e:=d.DialDatagram(ctx,target)
   if e!=nil{t.Fatal(e)}
   defer session.Close()
   _=session.conn.SetDeadline(time.Now().Add(5*time.Second))
   if e=session.WriteDatagram([]byte("ping"));e!=nil{t.Fatal(e)}
   message,e:=session.ReadDatagram()
   if e!=nil||string(message)!="pong"{t.Fatalf("encrypted UDP response %q %v",message,e)}
   if e=<-peerErr;e!=nil{t.Fatal(e)}
  })
 }
}
