// Package hysteria1 implements the separate Hysteria 1 binary-v3 wire format.
// It is not a replacement for Xray's original Hysteria 2 implementation.
package hysteria1

import (
    "bytes"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "errors"
    "io"
    "net"
    "strings"
)

const (
    WireVersion byte = 3
    MaxAuthBytes = 4096
    MaxAddressBytes = 253
    MaxMessageBytes = 4096
    MaxUDPPayload = 65507
    MaxFragments = 128
    MaxUDPFrameBytes = 997 // 1000-byte QUIC datagram minus framing overhead
)

var ErrWire = errors.New("hysteria1: malformed binary-v3 wire data")

type Hello struct {
    Code byte
    TX, RX uint64
    Message string
}
func validRate(n uint64) bool { return n>0 && n<=12500000000 }
func writeText(dst []byte, value string, limit int) ([]byte,error) {
    if len(value)>limit || len(value)>65535 {return nil,ErrWire}
    dst=binary.BigEndian.AppendUint16(dst,uint16(len(value)))
    return append(dst,value...),nil
}
func readText(r io.Reader,limit int)(string,error){
    var size [2]byte
    if _,err:=io.ReadFull(r,size[:]);err!=nil{return "",err}
    n:=int(binary.BigEndian.Uint16(size[:]))
    if n>limit{return "",ErrWire}
    b:=make([]byte,n)
    if _,err:=io.ReadFull(r,b);err!=nil{return "",err}
    return string(b),nil
}
func(h Hello)MarshalBinary()([]byte,error){
    if !validRate(h.TX)||!validRate(h.RX)||len(h.Message)>MaxAuthBytes{return nil,ErrWire}
    b:=[]byte{h.Code}
    b=binary.BigEndian.AppendUint64(b,h.TX)
    b=binary.BigEndian.AppendUint64(b,h.RX)
    return writeText(b,h.Message,MaxAuthBytes)
}
func ReadHello(r io.Reader)(Hello,error){
    var b [17]byte
    if _,err:=io.ReadFull(r,b[:]);err!=nil{return Hello{},err}
    h:=Hello{Code:b[0],TX:binary.BigEndian.Uint64(b[1:9]),RX:binary.BigEndian.Uint64(b[9:17])}
    var err error
    h.Message,err=readText(r,MaxAuthBytes)
    if err!=nil{return Hello{},err}
    if !validRate(h.TX)||!validRate(h.RX){return Hello{},ErrWire}
    return h,nil
}
type Request struct{UDP bool;Host string;Port uint16}
func validAddress(host string,port uint16,udp bool)bool{
    if udp&&host==""&&port==0{return true}
    if host==""||len(host)>MaxAddressBytes||port==0||strings.ContainsAny(host,"\x00\r\n\t /?#@%"){return false}
    if net.ParseIP(host)!=nil{return true}
    host=strings.TrimSuffix(host,".")
    if host==""{return false}
    for _,label:=range strings.Split(host,"."){
        if len(label)==0||len(label)>63||label[0]=='-'||label[len(label)-1]=='-'{return false}
        for _,c:=range label{
            if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='-'||c=='_'){return false}
        }
    }
    return true
}
func(q Request)MarshalBinary()([]byte,error){
    if !validAddress(q.Host,q.Port,q.UDP){return nil,ErrWire}
    b:=[]byte{0}
    if q.UDP{b[0]=1}
    b,err:=writeText(b,q.Host,MaxAddressBytes)
    if err!=nil{return nil,err}
    return binary.BigEndian.AppendUint16(b,q.Port),nil
}
func ReadRequest(r io.Reader)(Request,error){
    var typ [1]byte
    if _,err:=io.ReadFull(r,typ[:]);err!=nil{return Request{},err}
    if typ[0]>1{return Request{},ErrWire}
    host,err:=readText(r,MaxAddressBytes)
    if err!=nil{return Request{},err}
    var b [2]byte
    if _,err=io.ReadFull(r,b[:]);err!=nil{return Request{},err}
    q:=Request{UDP:typ[0]==1,Host:host,Port:binary.BigEndian.Uint16(b[:])}
    if !validAddress(q.Host,q.Port,q.UDP){return Request{},ErrWire}
    return q,nil
}
type Response struct {Accepted bool;SessionID uint32;Message string}
func(r Response)MarshalBinary()([]byte,error){
    b:=[]byte{0}
    if r.Accepted{b[0]=1}
    b=binary.BigEndian.AppendUint32(b,r.SessionID)
    return writeText(b,r.Message,MaxMessageBytes)
}
func ReadResponse(r io.Reader)(Response,error){
    var b [5]byte
    if _,err:=io.ReadFull(r,b[:]);err!=nil{return Response{},err}
    if b[0]>1{return Response{},ErrWire}
    msg,err:=readText(r,MaxMessageBytes)
    if err!=nil{return Response{},err}
    return Response{Accepted:b[0]==1,SessionID:binary.BigEndian.Uint32(b[1:]),Message:msg},nil
}
type UDPFrame struct {
    SessionID uint32
    Host string
    Port uint16
    PacketID uint16
    FragmentIndex,FragmentCount uint8
    Payload []byte
}
func(f UDPFrame)MarshalBinary()([]byte,error){
    if !validAddress(f.Host,f.Port,false)||f.FragmentCount==0||f.FragmentCount>MaxFragments||
        f.FragmentIndex>=f.FragmentCount||(f.FragmentCount>1&&f.PacketID==0)||len(f.Payload)>MaxUDPPayload{
        return nil,ErrWire
    }
    b:=binary.BigEndian.AppendUint32(nil,f.SessionID)
    var err error
    b,err=writeText(b,f.Host,MaxAddressBytes)
    if err!=nil{return nil,err}
    b=binary.BigEndian.AppendUint16(b,f.Port)
    b=binary.BigEndian.AppendUint16(b,f.PacketID)
    b=append(b,f.FragmentIndex,f.FragmentCount)
    b=binary.BigEndian.AppendUint16(b,uint16(len(f.Payload)))
    return append(b,f.Payload...),nil
}
func ParseUDPFrame(data []byte)(UDPFrame,error){
    if len(data)<14||len(data)>MaxUDPPayload+14+MaxAddressBytes{return UDPFrame{},ErrWire}
    f:=UDPFrame{SessionID:binary.BigEndian.Uint32(data[:4])}
    r:=bytes.NewReader(data[4:])
    var err error
    f.Host,err=readText(r,MaxAddressBytes)
    if err!=nil{return UDPFrame{},ErrWire}
    var h [8]byte
    if _,err=io.ReadFull(r,h[:]);err!=nil{return UDPFrame{},ErrWire}
    f.Port=binary.BigEndian.Uint16(h[:2])
    f.PacketID=binary.BigEndian.Uint16(h[2:4])
    f.FragmentIndex,f.FragmentCount=h[4],h[5]
    n:=int(binary.BigEndian.Uint16(h[6:8]))
    if !validAddress(f.Host,f.Port,false)||f.FragmentCount==0||f.FragmentCount>MaxFragments||
        f.FragmentIndex>=f.FragmentCount||(f.FragmentCount>1&&f.PacketID==0)||n!=r.Len()||n>MaxUDPPayload{
        return UDPFrame{},ErrWire
    }
    f.Payload=make([]byte,n)
    if _,err=io.ReadFull(r,f.Payload);err!=nil{return UDPFrame{},ErrWire}
    return f,nil
}
func SplitUDP(session uint32,packet uint16,host string,port uint16,payload []byte)([][]byte,error){
    if !validAddress(host,port,false)||len(payload)>MaxUDPPayload{return nil,ErrWire}
    size:=MaxUDPFrameBytes-(4+2+len(host)+2+2+1+1+2)
    if size<=0{return nil,ErrWire}
    count:=max(1,(len(payload)+size-1)/size)
    if count>MaxFragments||(count>1&&packet==0){return nil,ErrWire}
    out:=make([][]byte,0,count)
    for i:=0;i<count;i++{
        n:=min(size,len(payload))
        b,err:=(UDPFrame{SessionID:session,Host:host,Port:port,PacketID:packet,FragmentIndex:uint8(i),FragmentCount:uint8(count),Payload:payload[:n]}).MarshalBinary()
        if err!=nil||len(b)>MaxUDPFrameBytes{return nil,ErrWire}
        out=append(out,b)
        payload=payload[n:]
    }
    return out,nil
}
// XPlus is packet-level obfuscation, never authentication or encryption.
func XPlusEncode(key,payload []byte,entropy io.Reader)([]byte,error){
    if len(key)==0||entropy==nil||len(payload)>65519{return nil,ErrWire}
    b:=make([]byte,16+len(payload))
    if _,err:=io.ReadFull(entropy,b[:16]);err!=nil{return nil,err}
    xplusMask(key,b[:16],b[16:],payload)
    return b,nil
}
func XPlusDecode(key,wire []byte)([]byte,error){
    if len(key)==0||len(wire)<=16||len(wire)>65535{return nil,ErrWire}
    b:=make([]byte,len(wire)-16)
    xplusMask(key,wire[:16],b,wire[16:])
    return b,nil
}
func xplusMask(key,salt,dst,src []byte){
    h:=sha256.New()
    _,_=h.Write(key)
    _,_=h.Write(salt)
    sum:=h.Sum(nil)
    for i:=range src{dst[i]=src[i]^sum[i%len(sum)]}
}
func XPlusRandom(key,payload []byte)([]byte,error){return XPlusEncode(key,payload,rand.Reader)}
