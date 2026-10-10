//go:build linux

package nativego

import (
 "bufio"
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
 "net/http"
 "os"
 "os/exec"
 "strings"
 "testing"
 "time"
)

// Privileged, isolated *OS TCP* acceptance: Linux socket -> /dev/net/tun ->
// Go gVisor -> Go VLESS -> verified TLS peer -> HTTP/1.1 response -> TUN.
// No external Internet node and no changes to the host's main network.
func TestNativeGoLinuxRealTUNHTTP(t *testing.T){
 if os.Getenv("VPN_NATIVE_GO_PRIVILEGED_TEST")!="1"{t.Skip("isolated privileged Linux namespace only")}
 current,err:=os.Readlink("/proc/self/ns/net");if err!=nil{t.Fatal(err)}
 host,err:=os.Readlink("/proc/1/ns/net");if err!=nil{t.Fatal(err)}
 if current==host{t.Fatal("refusing to create routes on initial host namespace")}
 tun,err:=OpenNamedLinuxTUN("nativegoci1")
 if err!=nil{t.Fatal(err)}
 defer tun.Close()
 ip:=func(parts ...string){
  out,err:=exec.Command("ip",parts...).CombinedOutput()
  if err!=nil{t.Fatalf("isolated interface command %q: %v (%s)",parts,err,out)}
 }
 ip("addr","add","198.18.0.2/30","dev","nativegoci1")
 ip("link","set","dev","nativegoci1","up")
 ip("route","add","203.0.113.8/32","dev","nativegoci1")
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 certTemplate:=&x509.Certificate{
  SerialNumber:big.NewInt(711),Subject:pkix.Name{CommonName:"localhost"},DNSNames:[]string{"localhost"},
  NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),
  IsCA:true,BasicConstraintsValid:true,
  KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
 }
 der,err:=x509.CreateCertificate(rand.Reader,certTemplate,certTemplate,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
 pemPath:=t.TempDir()+"/trusted-nativego-ca.pem"
 if err=os.WriteFile(pemPath,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);err!=nil{t.Fatal(err)}
 t.Setenv("SSL_CERT_FILE",pemPath)
 certificate:=tls.Certificate{Certificate:[][]byte{der},PrivateKey:key}
 listener,err:=tls.Listen("tcp","127.0.0.1:0",&tls.Config{Certificates:[]tls.Certificate{certificate},MinVersion:tls.VersionTLS12})
 if err!=nil{t.Fatal(err)}
 defer listener.Close()
 result:=make(chan error,1)
 go func(){
  c,err:=listener.Accept()
  if err!=nil{result<-err;return}
  defer c.Close()
  _=c.SetDeadline(time.Now().Add(10*time.Second))
  header:=make([]byte,26)
  if _,err=io.ReadFull(c,header);err!=nil{result<-fmt.Errorf("VLESS header: %w",err);return}
  if header[0]!=0||header[18]!=1||header[19]!=0||header[20]!=80||header[21]!=1||
   string(header[22:26])!=string([]byte{203,0,113,8}){
   result<-fmt.Errorf("wrong authenticated VLESS target");return
  }
  req,err:=http.ReadRequest(bufio.NewReader(c))
  if err!=nil{result<-fmt.Errorf("tunneled HTTP request: %w",err);return}
  _=req.Body.Close()
  if req.Method!="GET"||req.URL.Path!="/go-native-proof"{
   result<-errors.New("wrong tunneled HTTP request");return
  }
  reply:=[]byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nHello World!")
  wire:=append([]byte{0,0},reply...)
  result<-writeFull(c,wire)
 }()
 node:=Node{Protocol:"vless",Address:"203.0.113.9",Port:443,ServerName:"localhost",
  Security:"tls",Transport:"raw",UUID:"00112233-4455-6677-8899-aabbccddeeff"}
 protected:=func(ctx context.Context,network,address string)(net.Conn,error){
  if network!="tcp"||address!="203.0.113.9:443"{return nil,errors.New("refusing unapproved node socket")}
  // Controlled peer resides on loopback inside the isolated network namespace.
  return (&net.Dialer{Timeout:5*time.Second}).DialContext(ctx,network,listener.Addr().String())
 }
 dialer,err:=NewDialer(node,protected);if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithCancel(context.Background())
 done:=make(chan error,1)
 go func(){done<-NewEngine(dialer,controlledDNS{}).Run(ctx,tun)}()
 client,err:=net.DialTimeout("tcp4","203.0.113.8:80",8*time.Second)
 if err!=nil{cancel();_=tun.Close();t.Fatalf("OS socket could not traverse real TUN: %v",err)}
 _=client.SetDeadline(time.Now().Add(10*time.Second))
 if _,err=client.Write([]byte("GET /go-native-proof HTTP/1.1\r\nHost: proof.local\r\nConnection: close\r\n\r\n"));err!=nil{
  cancel();_=client.Close();t.Fatal(err)
 }
 response,err:=http.ReadResponse(bufio.NewReader(client),&http.Request{Method:"GET"})
 if err!=nil{cancel();_=client.Close();t.Fatalf("HTTP did not return through gVisor: %v",err)}
 body,err:=io.ReadAll(io.LimitReader(response.Body,1024))
 _=response.Body.Close();_=client.Close()
 if err!=nil||response.StatusCode!=200||strings.TrimSpace(string(body))!="Hello World!"{
  cancel();t.Fatalf("real TUN HTTP wrong response status=%d body=%q error=%v",response.StatusCode,body,err)
 }
 select{
 case err=<-result:if err!=nil{t.Fatal(err)}
 case <-time.After(10*time.Second):t.Fatal("controlled encrypted peer did not complete")
 }
 cancel();_=tun.Close()
 select{
 case err=<-done:if !errors.Is(err,context.Canceled){t.Fatalf("engine did not shut down cleanly: %v",err)}
 case <-time.After(5*time.Second):t.Fatal("gVisor TUN workers leaked after HTTP proof")
 }
}
