//go:build linux

// Command nativego-linux is an opt-in Go-only native TUN process.
// The privileged hosting service MUST establish owned fail-closed nftables,
// interface addresses, full-tunnel routes and DNS before starting this process.
// No direct fallback, route mutations or insecure certificate overrides exist.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "net/netip"
 "os"
 "os/signal"
 "strings"
 "syscall"
 "time"

 "vpn-core/tls-provider/nativego"
)

func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"nativego-linux:",err);os.Exit(1)}}
func run()error{
 var nodeFile,uriFile,bootstrapIP,uplink string
 var fd,mtu,limit,mark int
 var policyReady bool
 flag.StringVar(&nodeFile,"node","","path to a private native Go node JSON (never logged)")
 flag.StringVar(&uriFile,"uri-file","","private original VLESS/Trojan URI file (never logged)")
 flag.StringVar(&bootstrapIP,"bootstrap-ip","","optional pre-resolved protected node IP before routing")
 flag.StringVar(&uplink,"uplink","","physical interface required for protected node sockets")
 flag.IntVar(&fd,"tun-fd",-1,"already configured application-owned TUN descriptor")
 flag.IntVar(&mtu,"mtu",1500,"TUN MTU")
 flag.IntVar(&limit,"max-flows",64,"maximum gVisor flows")
 flag.IntVar(&mark,"socket-mark",0,"nonzero socket mark allowed by owned nftables policy")
 flag.BoolVar(&policyReady,"policy-ready",false,"host certifies it installed an owned fail-closed policy")
 flag.Parse()
 if (nodeFile=="")== (uriFile=="") || uplink==""||fd<0||mark<=0||!policyReady {
  return errors.New("required: exactly one of -node/-uri-file, plus -uplink -tun-fd -socket-mark -policy-ready; no unprotected fallback")
 }
 if len(uplink)>15||strings.IndexByte(uplink,0)>=0{return errors.New("invalid physical interface name")}
 if _,err:=net.InterfaceByName(uplink);err!=nil{return fmt.Errorf("physical interface unavailable: %w",err)}
 var node nativego.Node
 if uriFile!=""{
  info,err:=os.Stat(uriFile);if err!=nil{return err}
  if info.Size()>65536{return errors.New("nativego: URI file too large")}
  body,err:=os.ReadFile(uriFile);if err!=nil{return err}
  node,err=nativego.ParseURI(strings.TrimSpace(string(body)))
  if err!=nil{return err}
 }else{
  file,err:=os.Open(nodeFile);if err!=nil{return err}
  defer file.Close()
  decoder:=json.NewDecoder(file);decoder.DisallowUnknownFields()
  if err=decoder.Decode(&node);err!=nil{return fmt.Errorf("private node config invalid: %w",err)}
 }
 actualIP:=node.Address
 if bootstrapIP!=""{
  ip,err:=nativego.EndpointIP(bootstrapIP);if err!=nil{return err}
  actualIP=ip.String()
 }else {
  if _,err:=nativego.EndpointIP(actualIP);err!=nil {
   return errors.New("hostname requires -bootstrap-ip, pre-resolved through protected physical network BEFORE VPN routing")
  }
 }
 protected:=func(ctx context.Context,network,address string)(net.Conn,error){
  if network!="tcp"||address!=net.JoinHostPort(node.Address,fmt.Sprint(node.Port)) {
   return nil,errors.New("unapproved underlay socket destination")
  }
  dialer:=net.Dialer{Timeout:10*time.Second}
  dialer.Control=func(network,address string,s syscall.RawConn)error{
   var controlErr error
   if err:=s.Control(func(fd uintptr){
    if er:=syscall.SetsockoptString(int(fd),syscall.SOL_SOCKET,syscall.SO_BINDTODEVICE,uplink);er!=nil{controlErr=er;return}
    if er:=syscall.SetsockoptInt(int(fd),syscall.SOL_SOCKET,syscall.SO_MARK,mark);er!=nil{controlErr=er}
   });err!=nil{return err}
   return controlErr
  }
  return dialer.DialContext(ctx,network,net.JoinHostPort(actualIP,fmt.Sprint(node.Port)))
 }
 d,err:=nativego.NewDialer(node,protected);if err!=nil{return err}
 device,err:=nativego.OpenBorrowedTunFD(fd);if err!=nil{return err}
 defer device.Close()
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
 defer stop()
 engine:=nativego.NewEngine(d,nativego.NewDoH(d))
 engine.MTU,engine.MaxFlows=mtu,limit
 fmt.Fprintln(os.Stderr,"nativego-linux: starting Go gVisor with protected encrypted node; host owns routes/firewall")
 err=engine.Run(ctx,device)
 if errors.Is(err,context.Canceled){return nil}
 return err
}
