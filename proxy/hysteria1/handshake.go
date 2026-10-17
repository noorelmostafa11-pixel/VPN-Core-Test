package hysteria1

import (
    "crypto/subtle"
    "errors"
    "io"
)
var (
    ErrAuthentication=errors.New("hysteria1: authentication rejected")
    ErrDestination=errors.New("hysteria1: destination rejected")
)
// Rates are bytes per second. Callers own connection timeouts and stream lifetime.
type Rates struct{Upload,Download uint64}
func writeFull(w io.Writer,p []byte)error{
    for len(p)>0{
        n,err:=w.Write(p)
        if n<0||n>len(p){return io.ErrShortWrite}
        p=p[n:]
        if err!=nil{return err}
        if n==0{return io.ErrShortWrite}
    }
    return nil
}
func ClientHandshake(s io.ReadWriter,password string,want Rates)(Rates,error){
    request,err:=(Hello{Code:WireVersion,TX:want.Upload,RX:want.Download,Message:password}).MarshalBinary()
    if err!=nil{return Rates{},err}
    if err=writeFull(s,request);err!=nil{return Rates{},err}
    reply,err:=ReadHello(s)
    if err!=nil{return Rates{},err}
    if reply.Code==0{return Rates{},ErrAuthentication}
    if reply.Code!=1||reply.TX>want.Download||reply.RX>want.Upload{return Rates{},ErrWire}
    return Rates{Upload:reply.RX,Download:reply.TX},nil
}
func ServerHandshake(s io.ReadWriter,password string,limit Rates)(Rates,error){
    request,err:=ReadHello(s)
    if err!=nil{return Rates{},err}
    if request.Code!=WireVersion||!validRate(limit.Upload)||!validRate(limit.Download){return Rates{},ErrWire}
    tx:=min(request.RX,limit.Upload)
    rx:=min(request.TX,limit.Download)
    ok:=subtle.ConstantTimeCompare([]byte(request.Message),[]byte(password))==1
    status:=byte(0)
    if ok{status=1}
    reply,err:=(Hello{Code:status,TX:tx,RX:rx}).MarshalBinary()
    if err!=nil{return Rates{},err}
    if err=writeFull(s,reply);err!=nil{return Rates{},err}
    if !ok{return Rates{},ErrAuthentication}
    return Rates{Upload:tx,Download:rx},nil
}
func RequestTCP(s io.ReadWriter,host string,port uint16)error{
    q,err:=(Request{Host:host,Port:port}).MarshalBinary()
    if err!=nil{return err}
    if err=writeFull(s,q);err!=nil{return err}
    response,err:=ReadResponse(s)
    if err!=nil{return err}
    if !response.Accepted{return ErrDestination}
    return nil
}
func RequestUDP(s io.ReadWriter)(uint32,error){
    q,_:=(Request{UDP:true}).MarshalBinary()
    if err:=writeFull(s,q);err!=nil{return 0,err}
    response,err:=ReadResponse(s)
    if err!=nil{return 0,err}
    if !response.Accepted{return 0,ErrDestination}
    if response.SessionID==0{return 0,ErrWire}
    return response.SessionID,nil
}
func SendResponse(w io.Writer,accepted bool,id uint32)error{
    q,err:=(Response{Accepted:accepted,SessionID:id}).MarshalBinary()
    if err!=nil{return err}
    return writeFull(w,q)
}
