package nativego

import (
 "bytes"
 "context"
 "errors"
 "fmt"
 "io"
 "net"
 "net/netip"
 "sync"
 "time"

 "gvisor.dev/gvisor/pkg/buffer"
 "gvisor.dev/gvisor/pkg/tcpip"
 "gvisor.dev/gvisor/pkg/tcpip/header"
 "gvisor.dev/gvisor/pkg/tcpip/link/channel"
 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
 "gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
 "gvisor.dev/gvisor/pkg/tcpip/stack"
 "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
 "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
 "gvisor.dev/gvisor/pkg/waiter"
)

// PacketDevice is a full IP packet device (one packet per Read/Write).
// The embedding host owns route, DNS and fail-closed firewall transactions.
type PacketDevice interface { io.ReadWriteCloser }
type Resolver interface { Resolve(context.Context, []byte)([]byte,error) }

type Engine struct {
 Dial *Dialer
 Resolver Resolver
 MTU int
 MaxFlows int
}

func NewEngine(d *Dialer,r Resolver)*Engine{return &Engine{Dial:d,Resolver:r,MTU:1500,MaxFlows:64}}

func (e *Engine) Run(parent context.Context, dev PacketDevice) error {
 if e==nil||e.Dial==nil||dev==nil{return errors.New("nativego: missing protected dialer or device")}
 mtu:=e.MTU;if mtu==0{mtu=1500};if mtu<1280||mtu>65535{return errors.New("nativego: invalid MTU")}
 maximum:=e.MaxFlows;if maximum==0{maximum=64};if maximum<1||maximum>256{return errors.New("nativego: invalid flow limit")}
 ctx,cancel:=context.WithCancel(parent);defer cancel()
 link:=channel.New(256,uint32(mtu),"")
 ns:=stack.New(stack.Options{
  NetworkProtocols:[]stack.NetworkProtocolFactory{ipv4.NewProtocol,ipv6.NewProtocol},
  TransportProtocols:[]stack.TransportProtocolFactory{tcp.NewProtocol,udp.NewProtocol},
  HandleLocal:false,
 })
 if err:=ns.CreateNIC(1,link);err!=nil{return fmt.Errorf("nativego: create NIC: %s",err)}
 if err:=ns.SetSpoofing(1,true);err!=nil{return fmt.Errorf("nativego: spoofing: %s",err)}
 if err:=ns.SetPromiscuousMode(1,true);err!=nil{return fmt.Errorf("nativego: promiscuous: %s",err)}
 ns.SetRouteTable([]tcpip.Route{{Destination:header.IPv4EmptySubnet,NIC:1},{Destination:header.IPv6EmptySubnet,NIC:1}})
 limit:=make(chan struct{},maximum)
 var workers sync.WaitGroup
 acquire:=func()bool{select{case limit<-struct{}{}:return true;default:return false}}
 release:=func(){<-limit}
 tf:=tcp.NewForwarder(ns,65536,maximum,func(req *tcp.ForwarderRequest){
  if !acquire(){req.Complete(true);return}
  workers.Add(1)
  go func(){
   defer workers.Done();defer release()
   id:=req.ID()
   var q waiter.Queue
   ep,err:=req.CreateEndpoint(&q)
   if err!=nil{req.Complete(true);return}
   req.Complete(false)
   defer ep.Close()
   target,targetErr:=flowTarget(id)
   if targetErr!=nil{return}
   e.serveTCP(ctx,ep,&q,target)
  }()
 })
 ns.SetTransportProtocolHandler(tcp.ProtocolNumber,tf.HandlePacket)
 ns.SetTransportProtocolHandler(udp.ProtocolNumber,func(id stack.TransportEndpointID,pkt *stack.PacketBuffer)bool{
  // CreateEndpoint must execute while the forwarder's original packet is live.
  req:=udp.NewForwarderRequest(ns,id,pkt)
  if !acquire(){return false}
  var q waiter.Queue
  ep,err:=req.CreateEndpoint(&q)
  if err!=nil{release();return false}
  target,targetErr:=flowTarget(req.ID())
  if targetErr!=nil{ep.Close();release();return false}
  workers.Add(1)
  go func(){
   defer workers.Done();defer release();defer ep.Close()
   e.serveUDP(ctx,ep,&q,target)
  }()
  return true
 })
 var stopOnce sync.Once
 stop:=func(){stopOnce.Do(func(){cancel();_=dev.Close()})}
 defer stop()
 var wg sync.WaitGroup
 wg.Add(1)
 go func(){defer wg.Done();<-ctx.Done();_=dev.Close()}()
 outputErr:=make(chan error,1)
 wg.Add(1)
 go func(){defer wg.Done()
  for{
   pkt:=link.ReadContext(ctx)
   if pkt==nil{return}
   out:=make([]byte,pkt.Size())
   if copied:=copyPacket(pkt,out);copied!=len(out){pkt.DecRef();select{case outputErr<-errors.New("nativego: packet view mismatch"):default:};stop();return}
   pkt.DecRef()
   n,err:=dev.Write(out)
   if err!=nil||n!=len(out){
    select{case outputErr<-fmt.Errorf("nativego: packet device write (%d/%d): %v",n,len(out),err):default:}
    stop();return
   }
  }
 }()
 input:=make([]byte,65535)
 var runErr error
loop:
 for {
  n,err:=dev.Read(input)
  if err!=nil{if ctx.Err()==nil{runErr=fmt.Errorf("nativego: TUN read: %w",err)};break loop}
  if n<20 {continue}
  var p tcpip.NetworkProtocolNumber
  switch input[0]>>4{case 4:p=header.IPv4ProtocolNumber;case 6:if n<40{continue};p=header.IPv6ProtocolNumber;default:continue}
  pkt:=stack.NewPacketBuffer(stack.PacketBufferOptions{Payload:buffer.MakeWithData(input[:n])})
  link.InjectInbound(p,pkt)
  pkt.DecRef()
  select {case err=<-outputErr:runErr=err;break loop;default:}
 }
 stop()
 ns.Close()
 for _,ep:=range ns.CleanupEndpoints(){ep.Abort()}
 workers.Wait()
 ns.Wait()
 link.Close()
 wg.Wait()
 if runErr==nil{select{case runErr=<-outputErr:default:}}
 if runErr!=nil{return runErr}
 if parent.Err()!=nil{return parent.Err()}
 return nil
}

func copyPacket(pkt *stack.PacketBuffer,out []byte)int{
 views,skip:=pkt.AsViewList()
 written:=0
 for v:=views.Front();v!=nil;v=v.Next(){
  b:=v.AsSlice()
  if skip>=len(b){skip-=len(b);continue}
  b=b[skip:];skip=0
  written+=copy(out[written:],b)
 }
 return written
}

func flowTarget(id stack.TransportEndpointID)(netip.AddrPort,error){
 a,ok:=netip.AddrFromSlice(id.LocalAddress.AsSlice())
 if !ok||id.LocalPort==0{return netip.AddrPort{},errors.New("nativego: bad forwarded destination")}
 return netip.AddrPortFrom(a,uint16(id.LocalPort)),nil
}
func ownedDNS(dest netip.AddrPort)bool{
 if dest.Port()!=53{return false}
 return dest.Addr()==netip.MustParseAddr("198.18.0.53")||dest.Addr()==netip.MustParseAddr("fd71:5650::53")
}

func (e *Engine) serveTCP(ctx context.Context, ep tcpip.Endpoint, q *waiter.Queue, dest netip.AddrPort) {
 var upstream net.Conn
 var err error
 if ownedDNS(dest) {
  if e.Resolver == nil { return }
  client, server := net.Pipe()
  upstream = client
  go func() { defer server.Close(); serveDNSStream(ctx, server, e.Resolver) }()
 } else {
  upstream, err = e.Dial.DialStream(ctx, dest)
  if err != nil { return }
 }
 defer upstream.Close()
 // A normal remote read EOF is only a half-close. Never cancel a pending
 // upload just because its independent download goroutine finished.
 flowCtx, cancel := context.WithCancel(ctx)
 defer cancel()
 failed := make(chan struct{}, 2)
 var relays sync.WaitGroup
 relays.Add(2)
 go func() {
  defer relays.Done()
  entry, ch := waiter.NewChannelEntry(waiter.EventIn | waiter.EventErr | waiter.EventHUp)
  q.EventRegister(&entry)
  defer q.EventUnregister(&entry)
  b := make([]byte, 32768)
  for {
   w := tcpip.SliceWriter(b)
   result, er := ep.Read(&w, tcpip.ReadOptions{})
   sent := 0
   for sent < result.Count {
    n, writeErr := upstream.Write(b[sent:result.Count])
    sent += n
    if writeErr != nil || n == 0 {
     failed <- struct{}{}
     return
    }
   }
   if _, ok := er.(*tcpip.ErrClosedForReceive); ok {
    if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
     if cw.CloseWrite() != nil { failed <- struct{}{} }
    }
    return
   }
   if _, ok := er.(*tcpip.ErrWouldBlock); ok {
    select { case <-ch: continue; case <-flowCtx.Done(): return }
   }
   if er != nil { failed <- struct{}{}; return }
   if result.Count == 0 {
    select { case <-ch: case <-flowCtx.Done(): return }
   }
  }
 }()
 go func() {
  defer relays.Done()
  entry, ch := waiter.NewChannelEntry(waiter.EventOut | waiter.EventErr | waiter.EventHUp)
  q.EventRegister(&entry)
  defer q.EventUnregister(&entry)
  b := make([]byte, 32768)
  for {
   n, er := upstream.Read(b)
   off := 0
   for off < n {
    accepted, writeErr := ep.Write(bytes.NewReader(b[off:n]), tcpip.WriteOptions{})
    off += int(accepted)
    if _, ok := writeErr.(*tcpip.ErrWouldBlock); ok {
     select { case <-ch: continue; case <-flowCtx.Done(): return }
    }
    if _, ok := writeErr.(*tcpip.ErrNoBufferSpace); ok {
     select { case <-ch: continue; case <-flowCtx.Done(): return }
    }
    if writeErr != nil || accepted == 0 { failed <- struct{}{}; return }
   }
   if er == io.EOF { _ = ep.Shutdown(tcpip.ShutdownWrite); return }
   if er != nil { failed <- struct{}{}; return }
  }
 }()
 done := make(chan struct{})
 go func() { relays.Wait(); close(done) }()
 timer := time.NewTimer(2 * time.Minute)
 defer timer.Stop()
 select {
 case <-done: // Both directions reached EOF: graceful full relay.
  return
 case <-failed: // A genuine relay failure needs immediate fail-close.
 case <-ctx.Done():
 case <-timer.C: // Bound unresponsive half-closed connections.
 }
 cancel()
 _ = upstream.Close()
 ep.Abort()
 <-done
}

func (e *Engine) serveUDP(ctx context.Context,ep tcpip.Endpoint,q *waiter.Queue,dest netip.AddrPort){
 if !ownedDNS(dest)||e.Resolver==nil{return} // All other UDP fails closed.
 entry,ch:=waiter.NewChannelEntry(waiter.EventIn|waiter.EventOut|waiter.EventErr)
 q.EventRegister(&entry);defer q.EventUnregister(&entry)
 b:=make([]byte,65535)
 timer:=time.NewTimer(30*time.Second);defer timer.Stop()
 for{
  w:=tcpip.SliceWriter(b)
  result,err:=ep.Read(&w,tcpip.ReadOptions{})
  if _,ok:=err.(*tcpip.ErrWouldBlock);ok{
   select{case <-ch:continue;case <-ctx.Done():return;case <-timer.C:return}
  }
  if err!=nil{return}
  if result.Count<12||result.Count>65535{return}
  query:=append([]byte(nil),b[:result.Count]...)
  queryCtx,cancel:=context.WithTimeout(ctx,10*time.Second)
  answer,er:=e.Resolver.Resolve(queryCtx,query)
  cancel()
  if er!=nil{answer=dnsFailure(query)}
  answer=limitDNSUDP(query,answer)
  // Atomic datagrams: never truncate or concatenate records.
  if len(answer)==0||len(answer)>65507{return}
  for len(answer)>0{
   n,writeErr:=ep.Write(bytes.NewReader(answer),tcpip.WriteOptions{Atomic:true})
   if writeErr==nil&&int(n)==len(answer){break}
   if _,ok:=writeErr.(*tcpip.ErrWouldBlock);!ok{return}
   select{case <-ch:case <-ctx.Done():return}
  }
  if !timer.Stop(){select{case <-timer.C:default:}}
  timer.Reset(30*time.Second)
 }
}
