package hysteria1

import (
    "bytes"
    "errors"
    "testing"
    "time"
)
func TestReassemblyOutOfOrder(t *testing.T){
    payload:=bytes.Repeat([]byte("packet"),600)
    frames,err:=SplitUDP(123,44,"example.invalid",443,payload)
    if err!=nil{t.Fatal(err)}
    a:=NewAssembler()
    for i:=len(frames)-1;i>=0;i--{
        f,err:=CanonicalFrame(frames[i])
        if err!=nil{t.Fatal(err)}
        d,ready,err:=a.Feed(f)
        if err!=nil{t.Fatal(err)}
        if ready!=(i==0){t.Fatal("wrong completion")}
        if ready&&!bytes.Equal(d.Payload,payload){t.Fatal("wrong payload")}
        if i>0{
            _,ready,err=a.Feed(f)
            if ready||err!=nil{t.Fatal("duplicate processed",err)}
        }
    }
    a.Close()
}
func TestReassemblyLimits(t *testing.T){
    a:=NewAssembler()
    now:=time.Now()
    a.clock=func()time.Time{return now}
    for i:=uint16(1);i<=MaxPendingPackets;i++{
        _,_,err:=a.Feed(UDPFrame{SessionID:1,PacketID:i,Host:"example.invalid",Port:443,FragmentCount:2,Payload:[]byte{1}})
        if err!=nil{t.Fatal(err)}
    }
    _,_,err:=a.Feed(UDPFrame{SessionID:1,PacketID:99,Host:"example.invalid",Port:443,FragmentCount:2,Payload:[]byte{1}})
    if !errors.Is(err,ErrWire){t.Fatal("missing limit",err)}
    now=now.Add(FragmentTTL+time.Second)
    _,_,err=a.Feed(UDPFrame{SessionID:1,PacketID:99,Host:"example.invalid",Port:443,FragmentCount:2,Payload:[]byte{1}})
    if err!=nil{t.Fatal("did not expire old messages",err)}
    a.Close()
}
