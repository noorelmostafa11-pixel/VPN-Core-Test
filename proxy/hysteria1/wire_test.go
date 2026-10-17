package hysteria1

import (
    "bytes"
    "errors"
    "testing"
)
func TestV3WireRoundTrips(t *testing.T){
    greeting:=Hello{Code:WireVersion,TX:12500000,RX:15000000,Message:"synthetic-secret"}
    b,err:=greeting.MarshalBinary()
    if err!=nil{t.Fatal(err)}
    got,err:=ReadHello(bytes.NewReader(b))
    if err!=nil||got!=greeting{t.Fatal(got,err)}
    for i:=0;i<len(b);i++{if _,err:=ReadHello(bytes.NewReader(b[:i]));err==nil{t.Fatal("truncation accepted")}}
    for _,r:=range []Request{{Host:"example.invalid",Port:443},{UDP:true}}{
        b,err:=r.MarshalBinary()
        if err!=nil{t.Fatal(err)}
        got,err:=ReadRequest(bytes.NewReader(b))
        if err!=nil||got!=r{t.Fatal(got,err)}
    }
    b,err=(Response{Accepted:true,SessionID:123}).MarshalBinary()
    if err!=nil{t.Fatal(err)}
    response,err:=ReadResponse(bytes.NewReader(b))
    if err!=nil||!response.Accepted||response.SessionID!=123{t.Fatal(response,err)}
}
func TestUDPFramesAndXPlus(t *testing.T){
    payload:=bytes.Repeat([]byte{1,2,3},20000)
    frames,err:=SplitUDP(42,7,"example.invalid",443,payload)
    if err!=nil{t.Fatal(err)}
    var back []byte
    for i,b:=range frames{
        if len(b)>MaxUDPFrameBytes{t.Fatal("oversized frame")}
        f,err:=ParseUDPFrame(b)
        if err!=nil||int(f.FragmentIndex)!=i{t.Fatal(err)}
        back=append(back,f.Payload...)
    }
    if !bytes.Equal(back,payload){t.Fatal("fragment bytes changed")}
    if _,err:=SplitUDP(42,0,"example.invalid",443,payload);!errors.Is(err,ErrWire){t.Fatal("missing packet ID accepted")}
    masked,err:=XPlusEncode([]byte("key"),payload,bytes.NewReader(bytes.Repeat([]byte{2},16)))
    if err!=nil{t.Fatal(err)}
    opened,err:=XPlusDecode([]byte("key"),masked)
    if err!=nil||!bytes.Equal(opened,payload){t.Fatal(err)}
}
func FuzzV3Frame(f *testing.F){
    b,_:=(UDPFrame{SessionID:1,Host:"example.invalid",Port:443,FragmentCount:1,Payload:[]byte("hello")}).MarshalBinary()
    f.Add(b)
    f.Add([]byte{0})
    f.Fuzz(func(t *testing.T,b []byte){
        p,err:=CanonicalFrame(b)
        if err==nil{
            canonical,e:=p.MarshalBinary()
            if e!=nil||!bytes.Equal(canonical,b){t.Fatal("noncanonical frame accepted")}
        }
    })
}
