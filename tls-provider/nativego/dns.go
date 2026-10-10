package nativego

import (
 "bytes"
 "context"
 "crypto/tls"
 "encoding/binary"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/netip"
 "time"
)

// DoH routes public DNS through the selected encrypted node TCP stream.
// Dialing arbitrary addresses, OS resolver fallback and insecure TLS are forbidden.
type DoH struct { dial *Dialer; client *http.Client }
func NewDoH(d *Dialer)*DoH{
 tr:=&http.Transport{
  Proxy:nil,
  TLSClientConfig:&tls.Config{ServerName:"cloudflare-dns.com",MinVersion:tls.VersionTLS12},
  ForceAttemptHTTP2:true,
  DialContext:func(ctx context.Context,network,address string)(net.Conn,error){
   if network!="tcp"||address!="cloudflare-dns.com:443"{return nil,errors.New("nativego: disallowed DoH target")}
   return d.DialStream(ctx,netip.MustParseAddrPort("1.1.1.1:443"))
  },
 }
 return &DoH{dial:d,client:&http.Client{Transport:tr,Timeout:12*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}}
}
func(d *DoH)Resolve(ctx context.Context,wire []byte)([]byte,error){
 if len(wire)<12||len(wire)>65535 {return nil,errors.New("nativego: invalid DNS input")}
 req,err:=http.NewRequestWithContext(ctx,http.MethodPost,"https://cloudflare-dns.com/dns-query",bytes.NewReader(wire))
 if err!=nil{return nil,err}
 req.Header.Set("Content-Type","application/dns-message")
 req.Header.Set("Accept","application/dns-message")
 resp,err:=d.client.Do(req);if err!=nil{return nil,err}
 defer resp.Body.Close()
 if resp.StatusCode!=200{return nil,fmt.Errorf("nativego: DNS upstream HTTP %d",resp.StatusCode)}
 if ct:=resp.Header.Get("Content-Type");ct!="application/dns-message"{return nil,errors.New("nativego: DNS upstream content type")}
 body,err:=io.ReadAll(io.LimitReader(resp.Body,65536));if err!=nil{return nil,err}
 if len(body)<12||len(body)>65535||!bytes.Equal(body[:2],wire[:2]){return nil,errors.New("nativego: DNS upstream mismatched reply")}
 return body,nil
}
func dnsFailure(query []byte)[]byte{
 reply:=make([]byte,12)
 if len(query)>=2{copy(reply,query[:2])}
 reply[2],reply[3]=0x81,0x82 // QR,RD / SERVFAIL; no misleading answer.
 return reply
}
func limitDNSUDP(query,answer []byte)[]byte{
 if len(answer)<=512{return answer}
 // Explicitly request TCP retry, preserve the full question, no invalid
 // partial resource record and no silent UDP truncation.
 if len(query)<12{return dnsFailure(query)}
 n:=12
 count:=int(binary.BigEndian.Uint16(query[4:6]))
 if count!=1{return dnsFailure(query)}
 for steps:=0;steps<128;steps++{
  if n>=len(query){return dnsFailure(query)}
  sz:=int(query[n]);n++
  if sz==0{break}
  if sz>63||n+sz>len(query){return dnsFailure(query)}
  n+=sz
 }
 if n+4>len(query)||n+4>512{return dnsFailure(query)}
 n+=4
 out:=make([]byte,n);copy(out,query[:n])
 out[2]=0x80|query[2]&1|0x02
 out[3]=0
 for i:=6;i<12;i++{out[i]=0} // answers, authority, additional
 return out
}
func serveDNSStream(ctx context.Context,conn net.Conn,res Resolver){
 for{
  var lenBuf [2]byte
  if _,err:=io.ReadFull(conn,lenBuf[:]);err!=nil{return}
  size:=int(binary.BigEndian.Uint16(lenBuf[:]));if size<12{return}
  query:=make([]byte,size)
  if _,err:=io.ReadFull(conn,query);err!=nil{return}
  rctx,cancel:=context.WithTimeout(ctx,10*time.Second)
  answer,err:=res.Resolve(rctx,query);cancel()
  if err!=nil{answer=dnsFailure(query)}
  if len(answer)>65535{return}
  binary.BigEndian.PutUint16(lenBuf[:],uint16(len(answer)))
  if _,err:=conn.Write(lenBuf[:]);err!=nil{return}
  if _,err:=conn.Write(answer);err!=nil{return}
 }
}
