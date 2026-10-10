//go:build linux

package nativego

import (
 "context"
 "encoding/binary"
 "errors"
 "fmt"
 "net"
 "os"
 "os/exec"
 "strings"
 "testing"
 "time"
)

// Privileged OS-network acceptance. Must run in a dedicated network namespace,
// never on a development machine's main network namespace. It verifies that
// actual Linux UDP packets enter /dev/net/tun, traverse gVisor -> Go DNS and
// return to the OS. No physical DNS or Internet traffic is generated.
func TestNativeGoLinuxRealTUNPacketDNS(t *testing.T){
 if os.Getenv("VPN_NATIVE_GO_PRIVILEGED_TEST")!="1"{t.Skip("run only inside a dedicated Linux network namespace")}
 current,err:=os.Readlink("/proc/self/ns/net");if err!=nil{t.Fatal(err)}
 initial,err:=os.Readlink("/proc/1/ns/net");if err!=nil{t.Fatal(err)}
 if current==initial{t.Fatal("refusing to modify host initial Linux network namespace")}
 device,err:=OpenNamedLinuxTUN("nativegoci0");if err!=nil{t.Fatalf("real TUN creation failed: %v",err)}
 defer device.Close()
 run:=func(args ...string){
  cmd:=exec.Command("ip",args...)
  if out,err:=cmd.CombinedOutput();err!=nil{t.Fatalf("isolated netns ip %v: %v (%s)",args,err,out)}
 }
 run("address","add","198.18.0.2/30","dev","nativegoci0")
 run("link","set","dev","nativegoci0","up")
 run("route","add","198.18.0.53/32","dev","nativegoci0")
 run("-6","address","add","fd71:5650::2/126","dev","nativegoci0","nodad")
 run("-6","route","add","fd71:5650::53/128","dev","nativegoci0")
 node:=Node{
  Protocol:"trojan",Address:"203.0.113.9",Port:443,ServerName:"example.com",
  Security:"tls",Transport:"raw",Password:"offline-prohibited",
 }
 protected:=func(context.Context,string,string)(net.Conn,error){return nil,errors.New("no physical-node dial allowed")}
 dialer,err:=NewDialer(node,protected);if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithCancel(context.Background())
 done:=make(chan error,1)
 go func(){done<-NewEngine(dialer,controlledDNS{}).Run(ctx,device)}()
 client,err:=net.DialTimeout("udp4","198.18.0.53:53",5*time.Second)
 if err!=nil{cancel();t.Fatalf("OS UDP to owned TUN DNS: %v",err)}
 defer client.Close()
 _=client.SetDeadline(time.Now().Add(8*time.Second))
 query:=[]byte{0xab,0xcd,1,0,0,1,0,0,0,0,0,0,1,'a',3,'c','o','m',0,0,1,0,1}
 if _,err=client.Write(query);err!=nil{cancel();t.Fatal(err)}
 received:=make([]byte,512)
 count,err:=client.Read(received)
 if err!=nil{cancel();t.Fatalf("real Linux TUN DNS reply was not received: %v",err)}
 if count<12||binary.BigEndian.Uint16(received[:2])!=0xabcd||received[2]&0x80==0{
  cancel();t.Fatalf("real TUN DNS response invalid (%d bytes): %s",count,strings.TrimSpace(fmt.Sprintf("%x",received[:count])))
 }
 // IPv6 DNS is a distinct OS packet path, not merely parser support.
 v6,err:=net.DialTimeout("udp6","[fd71:5650::53]:53",5*time.Second)
 if err!=nil{cancel();t.Fatalf("OS IPv6 UDP to owned TUN DNS: %v",err)}
 _=v6.SetDeadline(time.Now().Add(8*time.Second))
 query[0],query[1]=0xde,0xad
 if _,err=v6.Write(query);err!=nil{_=v6.Close();cancel();t.Fatal(err)}
 count,err=v6.Read(received)
 _=v6.Close()
 if err!=nil{cancel();t.Fatalf("real Linux IPv6 TUN DNS reply absent: %v",err)}
 if count<12||binary.BigEndian.Uint16(received[:2])!=0xdead||received[2]&0x80==0{
  cancel();t.Fatalf("real TUN IPv6 DNS response invalid: %x",received[:count])
 }
 cancel();_=device.Close()
 select{
 case err=<-done:
  if !errors.Is(err,context.Canceled){t.Fatalf("Go packet engine stop: %v",err)}
 case <-time.After(5*time.Second):t.Fatal("Go packet engine could not stop")
 }
}
