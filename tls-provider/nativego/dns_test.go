package nativego
import(
 "bytes"
 "context"
 "encoding/binary"
 "errors"
 "io"
 "net"
 "testing"
)
type fakeDNS struct{ output []byte; err error }
func(f fakeDNS)Resolve(context.Context,[]byte)([]byte,error){return f.output,f.err}
func TestFailClosedDNS(t *testing.T){
 x:=dnsFailure([]byte{0x12,0x34})
 if x[0]!=0x12||x[1]!=0x34||x[3]!=0x82{t.Fatalf("%x",x)}
}
func TestDNSUDPTruncation(t *testing.T){
 q:=[]byte{0x12,0x34,1,0,0,1,0,0,0,0,0,0,1,'a',0,0,1,0,1}
 long:=make([]byte,700)
 short:=limitDNSUDP(q,long)
 if len(short)!=len(q)||short[2]&2==0||binary.BigEndian.Uint16(short[6:8])!=0{t.Fatalf("incorrect truncation: %x",short)}
}
func TestDNSTCPFraming(t *testing.T){
 a,b:=net.Pipe();defer a.Close();defer b.Close()
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 go func(){serveDNSStream(ctx,b,fakeDNS{output:[]byte{0,1,0,0,0,0,0,0,0,0,0,0}})}()
 req:=make([]byte,12);req[0]=42
 frame:=append([]byte{0,12},req...)
 if _,err:=a.Write(frame);err!=nil{t.Fatal(err)}
 lenBuf:=make([]byte,2)
 if _,err:=io.ReadFull(a,lenBuf);err!=nil{t.Fatal(err)}
 size:=binary.BigEndian.Uint16(lenBuf)
 if size!=12{t.Fatal(size)}
 resp:=make([]byte,size)
 if _,err:=io.ReadFull(a,resp);err!=nil{t.Fatal(err)}
 if !bytes.Equal(resp,[]byte{0,1,0,0,0,0,0,0,0,0,0,0}){t.Fatalf("response %x",resp)}
}
func TestDoHDoesNotAllowUnprotected(t *testing.T){
 if _,err:=NewDialer(Node{},nil);!errors.Is(err,ErrUnprotected){t.Fatal(err)}
}
