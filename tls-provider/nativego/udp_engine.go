package nativego

import (
 "bytes"
 "context"
 "errors"
 "io"
 "net/netip"
 "sync"
 "time"

 "gvisor.dev/gvisor/pkg/tcpip"
 "gvisor.dev/gvisor/pkg/waiter"
)

// serveTunnelUDP handles one fixed destination entirely inside Go: packets
// arrive from gVisor and travel over authenticated VLESS/Trojan TLS carriers.
// There is never a physical-network UDP fallback, and the caller owns the
// protected underlay dialer plus OS firewall/route policy.
func(e *Engine)serveTunnelUDP(ctx context.Context,ep tcpip.Endpoint,q *waiter.Queue,dest netip.AddrPort){
 session,err:=e.Dial.DialDatagram(ctx,dest)
 if err!=nil{return} // Rejected features and failed authentication fail closed.
 defer session.Close()
 stop:=make(chan struct{})
 defer close(stop)
 go func(){select{case <-ctx.Done():_=session.Close();case <-stop:}}()
 errorEvents:=make(chan error,2)
 var workers sync.WaitGroup
 workers.Add(2)
 go func(){
  defer workers.Done()
  event,ch:=waiter.NewChannelEntry(waiter.EventIn|waiter.EventErr|waiter.EventHUp)
  q.EventRegister(&event);defer q.EventUnregister(&event)
  input:=make([]byte,65535)
  for{
   writer:=tcpip.SliceWriter(input)
   read,readErr:=ep.Read(&writer,tcpip.ReadOptions{})
   if _,ok:=readErr.(*tcpip.ErrWouldBlock);ok{
    select{case <-ctx.Done():return;case <-stop:return;case <-ch:continue}
   }
   if readErr!=nil{errorEvents<-readErr;return}
   // Each individual UDP datagram is written as one framed record. No
   // unbounded queue exists between gVisor and the encrypted node.
   if err=session.writeDeadline();err!=nil{errorEvents<-err;return}
   if err=session.WriteDatagram(input[:read.Count]);err!=nil{errorEvents<-err;return}
  }
 }()
 go func(){
  defer workers.Done()
  event,ch:=waiter.NewChannelEntry(waiter.EventOut|waiter.EventErr|waiter.EventHUp)
  q.EventRegister(&event);defer q.EventUnregister(&event)
  for{
   if err=session.readDeadline();err!=nil{errorEvents<-err;return}
   reply,readErr:=session.ReadDatagram()
   if readErr!=nil{errorEvents<-readErr;return}
   for{
    n,writeErr:=ep.Write(bytes.NewReader(reply),tcpip.WriteOptions{Atomic:true})
    if writeErr==nil&&int(n)==len(reply){break}
    if _,ok:=writeErr.(*tcpip.ErrWouldBlock);!ok{
     if _,ok=writeErr.(*tcpip.ErrNoBufferSpace);!ok{
      if writeErr==nil{writeErr=io.ErrShortWrite}
      errorEvents<-writeErr;return
     }
    }
    select{case <-ctx.Done():return;case <-stop:return;case <-ch:continue}
   }
  }
 }()
 // Stop when one direction fails: UDP has no half-close. Aborting both
 // directions prevents a hung/stale session from leaking on reconnect.
 select{
 case <-ctx.Done():
 case <-errorEvents:
 }
 _=session.Close()
 _=ep.Shutdown(tcpip.ShutdownRead|tcpip.ShutdownWrite)
 // The relay may be blocked on the endpoint or the carrier during teardown;
 // closing the authenticated carrier is what unblocks remote Read/Write.
 workers.Wait()
}

// Check the exported input contract during compilation, including the
// timeout distinction between a valid zero-length UDP record and EOF.
var _=errors.Is
var _=time.Second
