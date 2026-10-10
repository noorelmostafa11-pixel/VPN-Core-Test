// Package nativego is the isolated, in-process Go-native packet/data path.
// It is not enabled by the existing C++ application or SDK.
package nativego

import (
 "context"
 "crypto/sha256"
 "crypto/tls"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "net"
 "net/netip"
 "strings"
 "sync"
 "time"
)

var (
 ErrUnprotected = errors.New("nativego: protected underlay dialer is mandatory")
 ErrUnsupported = errors.New("nativego: node feature not implemented; fail closed")
)

// ProtectedDial MUST enforce the host application's underlay socket protection
// before connect. No implicit net.Dial fallback exists.
type ProtectedDial func(context.Context, string, string) (net.Conn, error)

type Node struct {
 Protocol string `json:"protocol"`
 Address string `json:"address"`
 Port uint16 `json:"port"`
 ServerName string `json:"server_name"`
 Security string `json:"security"`
 Transport string `json:"transport"`
 UUID string `json:"uuid,omitempty"`
 Password string `json:"password,omitempty"`
 Flow string `json:"flow,omitempty"`
 Fingerprint string `json:"fingerprint,omitempty"`
 Encryption string `json:"encryption,omitempty"`
}

type Dialer struct {
 node Node
 protected ProtectedDial
 uuid [16]byte
 passwordHash string
}

// NewDialer deliberately accepts only a proven narrow Go-native subset.
// Unimplemented REALITY, Vision, WS, VMess and Shadowsocks are rejected rather
// than silently downgraded to ordinary TLS or an unprotected network socket.
func NewDialer(n Node, protected ProtectedDial) (*Dialer, error) {
 if protected == nil { return nil, ErrUnprotected }
 if n.Port == 0 || n.Address == "" || n.ServerName == "" { return nil, fmt.Errorf("%w: incomplete node endpoint", ErrUnsupported) }
 if n.Security != "tls" || n.Transport != "raw" || n.Flow != "" || n.Fingerprint != "" { return nil, fmt.Errorf("%w: security/transport/flow", ErrUnsupported) }
 if n.Protocol != "vless" && n.Protocol != "trojan" { return nil, fmt.Errorf("%w: protocol %q", ErrUnsupported, n.Protocol) }
 if n.Protocol == "vless" && n.Encryption != "" && n.Encryption != "none" { return nil, fmt.Errorf("%w: VLESS encryption", ErrUnsupported) }
 d := &Dialer{node:n,protected:protected}
 if n.Protocol == "vless" {
  compact:=strings.ReplaceAll(n.UUID,"-","")
  id,err:=hex.DecodeString(compact)
  if err!=nil||len(id)!=16{return nil,errors.New("nativego: invalid VLESS UUID")}
  copy(d.uuid[:],id)
 } else {
  if n.Password=="" {return nil,errors.New("nativego: Trojan password missing")}
  h:=sha256.Sum224([]byte(n.Password))
  d.passwordHash=hex.EncodeToString(h[:])
 }
 return d,nil
}

// DialStream returns an encrypted, authenticated, protocol-ready TCP stream.
// HTTPS and VPN TLS verification cannot be disabled via configuration.
func (d *Dialer) DialStream(ctx context.Context, target netip.AddrPort) (net.Conn,error) {
 if !target.IsValid() || target.Port()==0 {return nil,errors.New("nativego: bad target")}
 nodeAddress:=net.JoinHostPort(d.node.Address,fmt.Sprint(d.node.Port))
 raw,err:=d.protected(ctx,"tcp",nodeAddress)
 if err!=nil{return nil,fmt.Errorf("nativego: protected connect: %w",err)}
 conn:=tls.Client(raw,&tls.Config{ServerName:d.node.ServerName,MinVersion:tls.VersionTLS12})
 if deadline,ok:=ctx.Deadline();ok{_ = conn.SetDeadline(deadline)}
 if err=conn.HandshakeContext(ctx);err!=nil{_ = conn.Close();return nil,fmt.Errorf("nativego: TLS authentication: %w",err)}
 _ = conn.SetDeadline(time.Time{})
 var frame []byte
 switch d.node.Protocol {
 case "vless": frame=vlessRequest(d.uuid,target)
 case "trojan": frame=trojanRequest(d.passwordHash,target)
 default: _=conn.Close();return nil,ErrUnsupported
 }
 if err=writeFull(conn,frame);err!=nil{_=conn.Close();return nil,err}
 if d.node.Protocol=="vless"{return &vlessResponseConn{Conn:conn},nil}
 return conn,nil
}

func destinationBytes(dest netip.AddrPort) []byte {
 a:=dest.Addr().Unmap()
 b:=make([]byte,0,19)
 b=append(b,byte(dest.Port()>>8),byte(dest.Port()))
 if a.Is4(){b=append(b,1)}else{b=append(b,3)}
 b=append(b,a.AsSlice()...)
 return b
}

func vlessRequest(uuid [16]byte,target netip.AddrPort) []byte {
 b:=make([]byte,0,40)
 b=append(b,0)
 b=append(b,uuid[:]...)
 b=append(b,0,1)
 return append(b,destinationBytes(target)...)
}
func trojanRequest(passwordHash string,target netip.AddrPort) []byte {
 b:=make([]byte,0,120)
 b=append(b,passwordHash...)
 b=append(b,13,10,1)
 // Trojan uses SOCKS5 address ordering: atyp + IP + port.
 d:=destinationBytes(target)
 b=append(b,d[2])
 b=append(b,d[3:]...)
 b=append(b,d[:2]...)
 return append(b,13,10)
}

type vlessResponseConn struct {
 net.Conn
 mu sync.Mutex
 once sync.Once
 headerErr error
}
func (c *vlessResponseConn) Read(b []byte)(int,error) {
 c.once.Do(func(){
  var header [2]byte
  if _,c.headerErr=io.ReadFull(c.Conn,header[:]);c.headerErr!=nil{return}
  if header[0]!=0 {c.headerErr=errors.New("nativego: invalid VLESS response version");return}
  if header[1]>0 {_,c.headerErr=io.CopyN(io.Discard,c.Conn,int64(header[1]))}
 })
 if c.headerErr!=nil{return 0,c.headerErr}
 return c.Conn.Read(b)
}
func(c *vlessResponseConn) CloseWrite()error{
 if cw,ok:=c.Conn.(interface{CloseWrite()error});ok{return cw.CloseWrite()}
 return nil // TLS 1.3 half-close is managed by the transport's lifecycle.
}

func writeFull(w io.Writer,data []byte) error {
 for len(data)>0 {
  n,err:=w.Write(data)
  if n>0{data=data[n:]}
  if err!=nil{return err}
  if n==0{return io.ErrShortWrite}
 }
 return nil
}
