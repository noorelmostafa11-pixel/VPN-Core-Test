package nativego

import (
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "fmt"
 "io"
 "math/big"
 "net"
 "net/netip"
 "os"
 "os/exec"
 "runtime"
 "strings"
 "testing"
 "time"
)

// Tests a real TLS handshake and the exact VLESS/Trojan stream wire against
// an authenticated, controlled peer. This is NOT a public Internet node test.
func TestNativeGoEncryptedPeer(t *testing.T){
 if runtime.GOOS=="windows" {t.Skip("controlled CA trust is verified on Linux")}
 if os.Getenv("VPN_NATIVE_GO_TEST_CHILD")!="1" {
  cmd:=exec.Command(os.Args[0],"-test.run=^TestNativeGoEncryptedPeer$","-test.v")
  cmd.Env=append(os.Environ(),"VPN_NATIVE_GO_TEST_CHILD=1")
  out,err:=cmd.CombinedOutput()
  if err!=nil{t.Fatalf("encrypted peer child: %v\n%s",err,out)}
  return
 }
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 template:=&x509.Certificate{
  SerialNumber:big.NewInt(1001),
  Subject:pkix.Name{CommonName:"example.com"},
  DNSNames:[]string{"example.com"},
  NotBefore:time.Now().Add(-time.Hour),
  NotAfter:time.Now().Add(time.Hour),
  KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
  BasicConstraintsValid:true,
  IsCA:true,
 }
 der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
 cert:=tls.Certificate{Certificate:[][]byte{der},PrivateKey:key}
 pemPath:=t.TempDir()+"/go-native-ca.pem"
 if err:=os.WriteFile(pemPath,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);err!=nil{t.Fatal(err)}
 t.Setenv("SSL_CERT_FILE",pemPath)
 for _,protocol:=range []string{"vless","trojan"}{
  t.Run(protocol,func(t *testing.T){
   ln,err:=tls.Listen("tcp","127.0.0.1:0",&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS12})
   if err!=nil{t.Fatal(err)}
   defer ln.Close()
   result:=make(chan error,1)
   go func(){
    s,err:=ln.Accept();if err!=nil{result<-err;return}
    defer s.Close()
    _=s.SetDeadline(time.Now().Add(5*time.Second))
    var sz int
    if protocol=="vless"{sz=26}else{sz=68}
    header:=make([]byte,sz)
    if _,err:=io.ReadFull(s,header);err!=nil{result<-fmt.Errorf("request header: %w",err);return}
    if protocol=="vless" {
     if header[0]!=0||header[18]!=1||header[21]!=1{result<-fmt.Errorf("unexpected VLESS header %x",header);return}
    } else {
     if !strings.Contains(string(header),string([]byte{13,10,1})){result<-fmt.Errorf("unexpected Trojan header %x",header);return}
    }
    msg:=make([]byte,4)
    if _,err:=io.ReadFull(s,msg);err!=nil{result<-err;return}
    if string(msg)!="ping"{result<-fmt.Errorf("unexpected payload %q",msg);return}
    if protocol=="vless"{_,err=s.Write([]byte{0,0,'p','o','n','g'})}else{_,err=s.Write([]byte("pong"))}
    result<-err
   }()
   n:=Node{Protocol:protocol,Address:"203.0.113.8",Port:443,ServerName:"example.com",Security:"tls",Transport:"raw",UUID:"00112233-4455-6677-8899-aabbccddeeff",Password:"test-password"}
   protected:=func(ctx context.Context,network,address string)(net.Conn,error){
    if network!="tcp"||address!="203.0.113.8:443"{return nil,errorsNew("unexpected external address")}
    return (&net.Dialer{}).DialContext(ctx,"tcp",ln.Addr().String())
   }
   d,err:=NewDialer(n,protected);if err!=nil{t.Fatal(err)}
   ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
   conn,err:=d.DialStream(ctx,netip.MustParseAddrPort("1.2.3.4:443"))
   if err!=nil{t.Fatal(err)}
   defer conn.Close()
   _=conn.SetDeadline(time.Now().Add(5*time.Second))
   if _,err=conn.Write([]byte("ping"));err!=nil{t.Fatal(err)}
   reply:=make([]byte,4)
   if _,err=io.ReadFull(conn,reply);err!=nil{t.Fatal(err)}
   if string(reply)!="pong"{t.Fatalf("wrong response %q",reply)}
   if err=<-result;err!=nil{t.Fatal(err)}
  })
 }
}
func errorsNew(s string)error{return fmt.Errorf("nativego-test: %s",s)}
