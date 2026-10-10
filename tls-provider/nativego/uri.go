package nativego

import (
 "errors"
 "fmt"
 "net"
 "net/netip"
 "net/url"
 "strconv"
 "strings"
)

// ParseURI is an opt-in, strict decoder for the currently supported raw
// VLESS/Trojan Go subset. It never rewrites the input URI and refuses unknown
// security/transport options instead of silently ignoring them. The legacy
// C++ parser remains authoritative for its wider compatibility surface.
func ParseURI(raw string)(Node,error){
 var n Node
 if len(raw)==0||len(raw)>65536{return n,errors.New("nativego: invalid URI length")}
 u,err:=url.Parse(strings.TrimSpace(raw))
 if err!=nil{return n,fmt.Errorf("nativego: invalid node URI: %w",err)}
 protocol:=strings.ToLower(u.Scheme)
 if protocol!="vless"&&protocol!="trojan"{return n,fmt.Errorf("%w: URI protocol",ErrUnsupported)}
 if u.User==nil||u.User.Username()==""||u.Hostname()==""||u.Port()==""{
  return n,errors.New("nativego: incomplete URI credentials/endpoint")
 }
 if _,ok:=u.User.Password();ok{return n,errors.New("nativego: unexpected URI password component")}
 port,err:=strconv.Atoi(u.Port())
 if err!=nil||port<1||port>65535{return n,errors.New("nativego: invalid node port")}
 if strings.ContainsAny(u.Hostname()," \t\r\n"){return n,errors.New("nativego: invalid host")}
 // A hostname is retained exactly as given. The host MUST bootstrap-resolve
 // it on the protected physical network before activating VPN routes.
 n=Node{Protocol:protocol,Address:u.Hostname(),Port:uint16(port),Transport:"raw"}
 if protocol=="trojan"{n.Password=u.User.Username()}else{n.UUID=u.User.Username();n.Encryption="none"}
 options:=make(map[string]string)
 parsed,err:=url.ParseQuery(u.RawQuery)
 if err!=nil{return Node{},fmt.Errorf("nativego: malformed URI query: %w",err)}
 if u.Path!=""&&u.Path!="/"{return Node{},fmt.Errorf("%w: URI path",ErrUnsupported)}
 for key,values:=range parsed{
  lower:=strings.ToLower(strings.TrimSpace(key))
  if lower==""||len(values)!=1{return Node{},errors.New("nativego: ambiguous URI option")}
  if _,exists:=options[lower];exists{return Node{},errors.New("nativego: duplicate URI option")}
  options[lower]=values[0]
 }
 used:=map[string]bool{}
 get:=func(keys ...string)string{
  for _,key:=range keys{if value,ok:=options[key];ok{used[key]=true;return value}}
  return ""
 }
 security:=strings.ToLower(get("security","tls"))
 if security==""&&protocol=="trojan"{security="tls"}
 if security!="tls"&&security!="reality"{return Node{},fmt.Errorf("%w: unsupported security",ErrUnsupported)}
 n.Security=security
 typ:=strings.ToLower(get("type","network","net"))
 if typ!=""&&typ!="tcp"&&typ!="raw"{return Node{},fmt.Errorf("%w: unsupported transport",ErrUnsupported)}
 n.ServerName=get("sni","servername","peer")
 if n.ServerName=="" {
  if _,err:=netip.ParseAddr(n.Address);err!=nil{n.ServerName=n.Address}
 }
 if n.ServerName==""{return Node{},errors.New("nativego: explicit SNI required for IP node address")}
 if strings.ContainsAny(n.ServerName," \t\r\n"){return Node{},errors.New("nativego: invalid TLS hostname")}
 n.Fingerprint=get("fp","fingerprint")
 n.PublicKey=get("pbk","publickey","public_key")
 n.ShortID=get("sid","shortid","short_id")
 n.PQVerify=get("pqv","pq_verify")
 n.Flow=get("flow")
 if e:=get("encryption");e!=""{n.Encryption=e}
 if alpn:=get("alpn");alpn!=""{
  for _,item:=range strings.Split(alpn,","){
   item=strings.TrimSpace(item)
   if item==""||len(item)>64{return Node{},errors.New("nativego: invalid ALPN")}
   n.ALPN=append(n.ALPN,item)
  }
 }
 if header:=strings.ToLower(get("headertype"));header!=""&&header!="none"{
  return Node{},fmt.Errorf("%w: unsupported TCP header",ErrUnsupported)
 }
 if insecure:=strings.ToLower(get("allowinsecure","insecure"));insecure!=""&&insecure!="0"&&insecure!="false"{
  return Node{},errors.New("nativego: TLS verification disable prohibited")
 }
 for key:=range options{
  if !used[key]{return Node{},fmt.Errorf("%w: unrecognized URI option %q",ErrUnsupported,key)}
 }
 // This parser intentionally never calls DNS, never connects and never
 // exposes credentials to logs. The caller must inject a protected dialer.
 return n,nil
}

// EndpointIP validates a pre-resolved physical-network bootstrap result.
// It can be used without changing the original URI or SNI.
func EndpointIP(text string)(net.IP,error){
 a,err:=netip.ParseAddr(text)
 if err!=nil||a.IsUnspecified()||a.IsMulticast(){return nil,errors.New("nativego: invalid protected bootstrap IP")}
 return net.IP(a.AsSlice()),nil
}
