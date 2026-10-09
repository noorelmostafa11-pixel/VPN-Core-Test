//go:build netstack

// Experimental packet stack only. Proxy parsing, encryption and transports
// remain in the project-owned C++ core. All buffers are copied across the ABI;
// no Go pointer is retained by C++ and no C++ buffer is retained by Go.
package main

/*
#include <stdint.h>
typedef struct {
    uint64_t id;
    uint32_t protocol;
    uint32_t address_size;
    uint8_t address[16];
    uint16_t port;
    uint16_t reserved;
} vpn_tun_flow;
*/
import "C"

import (
    "bytes"
    "encoding/json"
    "runtime"
    "sync"
    "sync/atomic"
    "unsafe"

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

type tunFlow struct {
    id uint64
    protocol uint32
    address []byte
    port uint16
    endpoint tcpip.Endpoint
    // UDP is peeked before consumption, so an undersized ABI buffer never
    // silently truncates a datagram. Calls for one stack are serialized.
}
type tunStack struct {
    mu sync.Mutex
    stack *stack.Stack
    link *channel.Endpoint
    closed bool
    limit int
    reserved int
    workers sync.WaitGroup
    flows map[uint64]*tunFlow
    pending []*tunFlow
    packet []byte
    scratch [65535]byte
    next uint64
    copiedIn atomic.Uint64
    copiedOut atomic.Uint64
    calls atomic.Uint64
}
var tunRegistry = struct {
    sync.Mutex
    next uint64
    stacks map[uint64]*tunStack
}{stacks: make(map[uint64]*tunStack)}

func tunLookup(id C.uint64_t) *tunStack {
    tunRegistry.Lock()
    defer tunRegistry.Unlock()
    return tunRegistry.stacks[uint64(id)]
}
func (t *tunStack) reserve() bool {
    t.mu.Lock()
    defer t.mu.Unlock()
    if t.closed || len(t.flows)+t.reserved >= t.limit { return false }
    t.reserved++
    // Add is protected by the same lock as the close transition.
    t.workers.Add(1)
    return true
}
func (t *tunStack) publish(ep tcpip.Endpoint, id stack.TransportEndpointID, protocol uint32) {
    t.mu.Lock()
    defer t.mu.Unlock()
    t.reserved--
    if ep == nil { return }
    if t.closed { ep.Abort(); return }
    t.next++
    f := &tunFlow{id:t.next, protocol:protocol, address:append([]byte(nil), id.LocalAddress.AsSlice()...), port:id.LocalPort, endpoint:ep}
    t.flows[f.id] = f
    t.pending = append(t.pending, f)
}

//export vpn_tun_abi_version
func vpn_tun_abi_version() C.int { return 1 }

//export vpn_tun_create
func vpn_tun_create(mtu C.int, maximum C.int) C.uint64_t {
    if mtu < 1280 || mtu > 65535 || maximum < 1 || maximum > 256 { return 0 }
    t := &tunStack{limit:int(maximum), flows:make(map[uint64]*tunFlow)}
    t.link = channel.New(256, uint32(mtu), "")
    t.stack = stack.New(stack.Options{
        NetworkProtocols:[]stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
        TransportProtocols:[]stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
        HandleLocal:false,
    })
    if err := t.stack.CreateNIC(1, t.link); err != nil { t.stack.Close(); return 0 }
    if err := t.stack.SetSpoofing(1,true); err != nil { t.stack.Close(); return 0 }
    if err := t.stack.SetPromiscuousMode(1,true); err != nil { t.stack.Close(); return 0 }
    t.stack.SetRouteTable([]tcpip.Route{{Destination:header.IPv4EmptySubnet,NIC:1},{Destination:header.IPv6EmptySubnet,NIC:1}})
    receive := tcpip.TCPReceiveBufferSizeRangeOption{Min:4096,Default:65536,Max:262144}
    send := tcpip.TCPSendBufferSizeRangeOption{Min:4096,Default:65536,Max:262144}
    if t.stack.SetTransportProtocolOption(tcp.ProtocolNumber,&receive) != nil || t.stack.SetTransportProtocolOption(tcp.ProtocolNumber,&send) != nil { t.stack.Close(); return 0 }
    tf := tcp.NewForwarder(t.stack,65536,int(maximum),func(r *tcp.ForwarderRequest) {
        if !t.reserve() { r.Complete(true); return }
        go func() {
            defer t.workers.Done()
            destination:=r.ID() // Complete releases the request's segment.
            var q waiter.Queue
            ep, err := r.CreateEndpoint(&q)
            if err != nil { r.Complete(true); t.publish(nil,destination,6); return }
            r.Complete(false)
            t.publish(ep,destination,6)
        }()
    })
    t.stack.SetTransportProtocolHandler(tcp.ProtocolNumber,tf.HandlePacket)
    t.stack.SetTransportProtocolHandler(udp.ProtocolNumber,func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
        // Synchronous endpoint creation borrows the dispatcher's packet.
        // Avoid the stock forwarder's extra cloned PacketBuffer reference.
        r:=udp.NewForwarderRequest(t.stack,id,pkt)
        if !t.reserve() { return false }
        defer t.workers.Done()
        var q waiter.Queue
        ep, err := r.CreateEndpoint(&q)
        if err != nil { t.publish(nil,r.ID(),17); return false }
        t.publish(ep,r.ID(),17)
        return true
    })
    tunRegistry.Lock()
    defer tunRegistry.Unlock()
    tunRegistry.next++
    tunRegistry.stacks[tunRegistry.next]=t
    return C.uint64_t(tunRegistry.next)
}

//export vpn_tun_close
func vpn_tun_close(id C.uint64_t) {
    tunRegistry.Lock()
    t:=tunRegistry.stacks[uint64(id)]
    delete(tunRegistry.stacks,uint64(id))
    tunRegistry.Unlock()
    if t==nil {return}
    t.mu.Lock()
    t.closed=true
    for _,f:=range t.flows {f.endpoint.Abort()}
    t.flows=nil; t.pending=nil; t.packet=nil
    t.mu.Unlock()
    t.stack.Close()
    for _,ep:=range t.stack.CleanupEndpoints(){ep.Abort()}
    t.workers.Wait()
    t.stack.Wait()
    t.link.Close()
}

//export vpn_tun_inject
func vpn_tun_inject(id C.uint64_t, data *C.uint8_t, size C.int) C.int {
    t:=tunLookup(id)
    if t==nil || data==nil || size<20 || size>65535 {return -1}
    // Never hold t.mu across synchronous transport handlers.
    p:=C.GoBytes(unsafe.Pointer(data),size)
    protocol:=header.IPv4ProtocolNumber
    switch p[0]>>4 {case 4: case 6: if size<40{return -1}; protocol=header.IPv6ProtocolNumber; default:return -1}
    pkt:=stack.NewPacketBuffer(stack.PacketBufferOptions{Payload:buffer.MakeWithData(p)})
    defer pkt.DecRef()
    t.calls.Add(1);t.copiedIn.Add(uint64(size))
    t.link.InjectInbound(protocol,pkt)
    return size
}

//export vpn_tun_packet
func vpn_tun_packet(id C.uint64_t, out *C.uint8_t, capacity C.int) C.int {
    t:=tunLookup(id)
    if t==nil || out==nil || capacity<1 {return -1}
    t.mu.Lock();defer t.mu.Unlock()
    if t.closed{return -1}
    if len(t.packet)==0 {
        p:=t.link.Read(); if p==nil{return -2}
        v:=p.ToView();t.packet=append([]byte(nil),v.AsSlice()...);v.Release();p.DecRef()
    }
    if len(t.packet)>int(capacity){return -3}
    n:=copy(unsafe.Slice((*byte)(unsafe.Pointer(out)),int(capacity)),t.packet)
    t.packet=nil;t.calls.Add(1);t.copiedOut.Add(uint64(n));return C.int(n)
}

//export vpn_tun_accept
func vpn_tun_accept(id C.uint64_t, out *C.vpn_tun_flow) C.int {
    t:=tunLookup(id);if t==nil || out==nil{return -1}
    t.mu.Lock();defer t.mu.Unlock()
    if t.closed{return -1}
    for len(t.pending)>0 {
        f:=t.pending[0];t.pending=t.pending[1:]
        if t.flows[f.id]==nil{continue}
        *out=C.vpn_tun_flow{}
        out.id=C.uint64_t(f.id);out.protocol=C.uint32_t(f.protocol)
        out.address_size=C.uint32_t(len(f.address));out.port=C.uint16_t(f.port)
        for i,b:=range f.address {out.address[i]=C.uint8_t(b)}
        t.calls.Add(1);return 1
    }
    return -2
}

//export vpn_tun_read
func vpn_tun_read(id C.uint64_t, flow C.uint64_t, out *C.uint8_t, capacity C.int) C.int {
    t:=tunLookup(id);if t==nil || out==nil || capacity<1 || capacity>65535{return -1}
    t.mu.Lock();defer t.mu.Unlock()
    f:=t.flows[uint64(flow)];if f==nil{return -1}
    // A fixed-size Go-owned buffer bounds copying and does not expose C memory
    // to a retained endpoint. UDP empty datagrams remain distinct from EOF.
    b:=t.scratch[:int(capacity)];w:=tcpip.SliceWriter(b)
    opts:=tcpip.ReadOptions{}
    if f.protocol==17 {
        opts.Peek=true
        peek,err:=f.endpoint.Read(&w,opts)
        if _,ok:=err.(*tcpip.ErrWouldBlock);ok{return -2}
        if err!=nil{return -1}
        if peek.Total>int(capacity){return -3}
        w=tcpip.SliceWriter(b);opts.Peek=false
    }
    r,err:=f.endpoint.Read(&w,opts)
    if _,ok:=err.(*tcpip.ErrWouldBlock);ok{return -2}
    if _,ok:=err.(*tcpip.ErrClosedForReceive);ok{return -4}
    if err!=nil{return -1}
    copy(unsafe.Slice((*byte)(unsafe.Pointer(out)),int(capacity)),b[:r.Count])
    t.calls.Add(1);t.copiedOut.Add(uint64(r.Count));return C.int(r.Count)
}

//export vpn_tun_write
func vpn_tun_write(id C.uint64_t, flow C.uint64_t, data *C.uint8_t, size C.int) C.int {
    t:=tunLookup(id);if t==nil || (data==nil && size>0) || size<0 || size>65507{return -1}
    t.mu.Lock();defer t.mu.Unlock()
    f:=t.flows[uint64(flow)];if f==nil{return -1}
    p:=C.GoBytes(unsafe.Pointer(data),size)
    n,err:=f.endpoint.Write(bytes.NewReader(p),tcpip.WriteOptions{Atomic:f.protocol==17})
    if _,ok:=err.(*tcpip.ErrWouldBlock);ok{return -2}
    if err!=nil{return -1}
    t.calls.Add(1);t.copiedIn.Add(uint64(n));return C.int(n)
}

//export vpn_tun_shutdown_write
func vpn_tun_shutdown_write(id C.uint64_t, flow C.uint64_t) C.int {
    t:=tunLookup(id);if t==nil{return -1}
    t.mu.Lock();defer t.mu.Unlock()
    f:=t.flows[uint64(flow)];if f==nil{return -1}
    if f.endpoint.Shutdown(tcpip.ShutdownWrite)!=nil{return -1};return 0
}

//export vpn_tun_drop
func vpn_tun_drop(id C.uint64_t, flow C.uint64_t) {
    t:=tunLookup(id);if t==nil{return}
    t.mu.Lock();defer t.mu.Unlock()
    if f:=t.flows[uint64(flow)];f!=nil{f.endpoint.Abort();delete(t.flows,uint64(flow))}
}

//export vpn_tun_release
func vpn_tun_release(id C.uint64_t, flow C.uint64_t) {
    t:=tunLookup(id);if t==nil{return}
    t.mu.Lock();defer t.mu.Unlock()
    // Graceful TCP teardown preserves queued FIN/data until the peer ACKs.
    if f:=t.flows[uint64(flow)];f!=nil{f.endpoint.Close();delete(t.flows,uint64(flow))}
}

//export vpn_tun_metrics
func vpn_tun_metrics(id C.uint64_t, out *C.uint8_t, capacity C.int) C.int {
    t:=tunLookup(id);if t==nil || out==nil || capacity<1{return -1}
    var memory runtime.MemStats;runtime.ReadMemStats(&memory)
    t.mu.Lock();active:=len(t.flows);reserved:=t.reserved;t.mu.Unlock()
    b,_:=json.Marshal(map[string]uint64{"abi_calls":t.calls.Load(),"copied_to_go_bytes":t.copiedIn.Load(),"copied_to_cpp_bytes":t.copiedOut.Load(),"active_flows":uint64(active),"pending_handshakes":uint64(reserved),"go_heap_alloc_bytes":memory.HeapAlloc,"go_heap_sys_bytes":memory.HeapSys,"go_total_alloc_bytes":memory.TotalAlloc,"go_goroutines":uint64(runtime.NumGoroutine()),"go_gc_count":uint64(memory.NumGC)})
    if len(b)>int(capacity){return -3}
    return C.int(copy(unsafe.Slice((*byte)(unsafe.Pointer(out)),int(capacity)),b))
}

//export vpn_tun_copy_probe
func vpn_tun_copy_probe(input *C.uint8_t, output *C.uint8_t, size C.int) C.int {
    if input==nil || output==nil || size<0 || size>65535{return -1}
    b:=C.GoBytes(unsafe.Pointer(input),size)
    return C.int(copy(unsafe.Slice((*byte)(unsafe.Pointer(output)),int(size)),b))
}
