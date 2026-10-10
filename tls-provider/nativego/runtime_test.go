package nativego

import (
 "context"
 "errors"
 "io"
 "net"
 "net/netip"
 "sync"
 "testing"
 "time"
)

type blockedTun struct{
 once sync.Once
 closed chan struct{}
}
func(d *blockedTun)Read([]byte)(int,error){<-d.closed;return 0,io.EOF}
func(d *blockedTun)Write(b []byte)(int,error){return len(b),nil}
func(d *blockedTun)Close()error{d.once.Do(func(){close(d.closed)});return nil}

func TestNativeGoStackRepeatedLifecycle(t *testing.T){
 node:=Node{Protocol:"trojan",Address:"203.0.113.20",Port:443,ServerName:"example.com",Security:"tls",Transport:"raw",Password:"never-connect"}
 dialer,err:=NewDialer(node,func(context.Context,string,string)(net.Conn,error){
  t.Error("unexpected unprotected node call during empty TUN lifecycle")
  return nil,ErrUnprotected
 })
 if err!=nil{t.Fatal(err)}
 for i:=0;i<8;i++{
  ctx,cancel:=context.WithCancel(context.Background())
  dev:=&blockedTun{closed:make(chan struct{})}
  done:=make(chan error,1)
  go func(){done<-NewEngine(dialer,nil).Run(ctx,dev)}()
  time.Sleep(10*time.Millisecond)
  cancel()
  select{
  case err:=<-done:
   if !errors.Is(err,context.Canceled){t.Fatalf("cycle %d unexpected shutdown: %v",i,err)}
  case <-time.After(3*time.Second):
   t.Fatalf("cycle %d: Go native stack did not shut down",i)
  }
 }
}
func TestOwnedResolverMatch(t *testing.T){
 for _,text:=range []string{"198.18.0.53:53","[fd71:5650::53]:53"}{
  if !ownedDNS(netip.MustParseAddrPort(text)){t.Fatal(text)}
 }
 for _,text:=range []string{"8.8.8.8:53","198.18.0.53:443","[fd71:5650::2]:53"}{
  if ownedDNS(netip.MustParseAddrPort(text)){t.Fatal("intercepted unrelated DNS:",text)}
 }
}
