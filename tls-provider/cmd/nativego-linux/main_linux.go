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
 var nodeFile, uplink string
 var fd,mtu,limit,mark int
 var policyReady bool
 flag.StringVar(&nodeFile,"node","","path to a private native Go node JSON (never logged)")
 flag.StringVar(&uplink,"uplink","","physical interface required for protected node sockets")
 flag.IntVar(&fd,"tun-fd",-1,"already configured application-owned TUN descriptor")
 flag.IntVar(&mtu,"mtu",1500,"TUN MTU")
 flag.IntVar(&limit,"max-flows",64,"maximum gVisor flows")
 flag.IntVar(&mark,"socket-mark",0,"nonzero socket mark allowed by owned nftables policy")
 flag.BoolVar(&policyReady,"policy-ready",false,"host certifies it installed an owned fail-closed policy")
 flag.Parse()
 if nodeFile==""||uplink==""||fd<0||mark<=0||!policyReady {
  return errors.New("required: -node -uplink -tun-fd -socket-mark -policy-ready; no unprotected fallback")
 }
 if len(uplink)>15||strings.IndexByte(uplink,0)>=0{return errors.New("invalid physical interface name")}
 if _,err:=net.InterfaceByName(uplink);err!=nil{return fmt.Errorf("physical interface unavailable: %w",err)}
 f,err:=os.Open(nodeFile);if err!=nil{return err}
 defer f.Close()
 var node nativego.Node
 dec:=json.NewDecoder(f);dec.DisallowUnknownFields()
 if err=dec.Decode(&node);err!=nil{return fmt.Errorf("private node config invalid: %w",err)}
 if _,err=netip.ParseAddr(node.Address);err!=nil {
  return errors.New("node bootstrap address must be an IP literal; resolve protected bootstrap BEFORE routing")
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
  return dialer.DialContext(ctx,network,address)
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
