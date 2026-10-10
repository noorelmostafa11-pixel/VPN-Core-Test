package nativego

import (
 "context"
 "encoding/binary"
 "errors"
 "net"
 "sync"
 "testing"
 "time"
)

// A real IPv4 UDP packet is injected through the Go-only packet device,
// forwarded by gVisor to the Go DNS resolver, then returned as an IP reply.
// This is an in-memory packet-network test, not OS routing or public Internet.
type packetLoopDevice struct {
 input chan []byte
 output chan []byte
 stopped chan struct{}
 once sync.Once
}
func newPacketLoopDevice()*packetLoopDevice{return &packetLoopDevice{input:make(chan []byte,8),output:make(chan []byte,8),stopped:make(chan struct{})}}
func(d *packetLoopDevice)Read(buf []byte)(int,error){
 select{
 case p:=<-d.input: return copy(buf,p),nil
 case <-d.stopped:return 0,errors.New("device closed")
 }
}
func(d *packetLoopDevice)Write(p []byte)(int,error){
 b:=append([]byte(nil),p...)
 select{
 case d.output<-b:return len(p),nil
 case <-d.stopped:return 0,errors.New("device closed")
 }
}
func(d *packetLoopDevice)Close()error{d.once.Do(func(){close(d.stopped)});return nil}
type controlledDNS struct{}
func(controlledDNS)Resolve(_ context.Context,q []byte)([]byte,error){
 if len(q)<12{return nil,errors.New("truncated query")}
 a:=append([]byte(nil),q...)
 a[2]=0x81;a[3]=0x80
 return a,nil
}
func ipv4Checksum(b []byte)uint16{
 var sum uint32
 for i:=0;i+1<len(b);i+=2{sum+=uint32(binary.BigEndian.Uint16(b[i:i+2]))}
 if len(b)%2!=0{sum+=uint32(b[len(b)-1])<<8}
 for sum>>16!=0{sum=(sum&0xffff)+(sum>>16)}
 return ^uint16(sum)
}
func makeIPv4DNSPacket(query []byte)[]byte{
 p:=make([]byte,28+len(query))
 p[0]=0x45;p[8]=64;p[9]=17
 binary.BigEndian.PutUint16(p[2:4],uint16(len(p)))
 copy(p[12:16],[]byte{198,18,0,2})
 copy(p[16:20],[]byte{198,18,0,53})
 binary.BigEndian.PutUint16(p[10:12],ipv4Checksum(p[:20]))
 binary.BigEndian.PutUint16(p[20:22],40000)
 binary.BigEndian.PutUint16(p[22:24],53)
 binary.BigEndian.PutUint16(p[24:26],uint16(len(p)-20))
 // UDP checksum zero is valid in IPv4 (unlike IPv6), so the test proves
 // the full packet path without relying on locally offloaded checksums.
 copy(p[28:],query)
 return p
}
func TestNativeGoIPv4PacketDNSRoundTrip(t *testing.T){
 node:=Node{Protocol:"vless",Address:"203.0.113.9",Port:443,ServerName:"example.com",Security:"tls",Transport:"raw",UUID:"00112233-4455-6677-8899-aabbccddeeff"}
 dialer,err:=NewDialer(node,func(context.Context,string,string)(net.Conn,error){
  t.Error("DNS-only owned endpoint must never dial physical node directly")
  return nil,ErrUnprotected
 })
 if err!=nil{t.Fatal(err)}
 device:=newPacketLoopDevice()
 ctx,cancel:=context.WithCancel(context.Background())
 done:=make(chan error,1)
 go func(){done<-NewEngine(dialer,controlledDNS{}).Run(ctx,device)}()
 query:=[]byte{0x12,0x34,1,0,0,1,0,0,0,0,0,0,1,'a',3,'c','o','m',0,0,1,0,1}
 select{
 case device.input<-makeIPv4DNSPacket(query):
 case <-time.After(2*time.Second):cancel();t.Fatal("TUN input queue blocked")
 }
 select{
 case out:=<-device.output:
  if len(out)<28||out[0]>>4!=4||out[9]!=17{t.Fatalf("not an IPv4 UDP DNS response: %x",out)}
  if string(out[12:16])!=string([]byte{198,18,0,53})||string(out[16:20])!=string([]byte{198,18,0,2}){t.Fatalf("DNS packet escaped wrong endpoint: %x",out[:20])}
  if binary.BigEndian.Uint16(out[20:22])!=53||binary.BigEndian.Uint16(out[22:24])!=40000{t.Fatalf("unexpected UDP reply ports: %x",out[20:28])}
  if len(out)<28+len(query)||out[28]!=0x12||out[29]!=0x34||out[30]&0x80==0{
   t.Fatalf("DNS reply missing or unauthenticated: %x",out[28:])
  }
 case <-time.After(5*time.Second):
  cancel();_=device.Close();t.Fatal("no gVisor -> Go resolver -> TUN UDP packet; Internet path is blocked")
 }
 cancel();_=device.Close()
 select{
 case <-done:
 case <-time.After(5*time.Second):t.Fatal("Go TUN packet engine did not stop")
 }
}
