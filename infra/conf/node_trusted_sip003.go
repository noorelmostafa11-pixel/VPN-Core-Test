package conf

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/infra/conf/sip003"
)

// ParseNodeURIWithTrustedSIP003 is an explicit application-only API.
// Ordinary node import never runs or selects a local executable.
func ParseNodeURIWithTrustedSIP003(ctx context.Context, uri string, approved sip003.Approved) (*OutboundDetourConfig, io.Closer, error) {
	node, err := DescribeNodeURI(uri)
	if err != nil { return nil,nil,err }
	return ResolveNodeWithTrustedSIP003(ctx,node,approved)
}

// ResolveNodeWithTrustedSIP003 uses a locally SHA256-pinned executable for
// authentic SIP003 wire framing. It never guesses whether basic WS is the same
// as v2ray-plugin mux, obfs-local HTTP/TLS or another third-party mode.
func ResolveNodeWithTrustedSIP003(ctx context.Context, node *NodeDescription, approved sip003.Approved) (*OutboundDetourConfig, io.Closer, error) {
	if node==nil || !strings.EqualFold(node.Protocol,"ss") {
		return nil,nil,errors.New("trusted SIP003: only Shadowsocks can use SIP003")
	}
	clean:=*node
	clean.Parameters=make(map[string]string,len(node.Parameters)+2)
	raw:=""
	seen:=false
	for key,value:=range node.Parameters {
		switch strings.ToLower(key) {
		case "plugin":
			if seen{return nil,nil,errors.New("trusted SIP003: duplicate plugin")}
			raw,seen=value,true
		case "ps","name","remarks","group":
			clean.Parameters[key]=value
		default:
			return nil,nil,errors.New("trusted SIP003: untrusted transport settings beside plugin")
		}
	}
	if !seen{return nil,nil,errors.New("trusted SIP003: missing plugin")}
	options,err:=trustedSIP003Options(raw,approved)
	if err!=nil{return nil,nil,err}
	clean.Parameters["type"]="tcp"
	clean.Parameters["security"]="none"
	// Validate original credentials and destination before executing anything.
	if _,err:=ResolveNode(&clean);err!=nil {
		return nil,nil,errors.New("trusted SIP003: invalid Shadowsocks connection data")
	}
	process,err:=sip003.Start(ctx,approved,node.Address,node.Port,options)
	if err!=nil{return nil,nil,err}
	clean.Address="127.0.0.1"
	clean.Port=process.LocalPort
	selection,err:=ResolveNode(&clean)
	if err!=nil{
		_ = process.Close()
		return nil,nil,errors.New("trusted SIP003: failed to build loopback Shadowsocks node")
	}
	return selection.Outbound,process,nil
}

func trustedSIP003Options(raw string, approved sip003.Approved) (string,error) {
	if raw==""||len(raw)>2048||strings.ContainsAny(raw,"\x00\r\n") {
		return "",errors.New("trusted SIP003: invalid plugin name/options")
	}
	parts:=strings.Split(raw,";")
	name:=parts[0]
	if name!=approved.Name && !(name=="simple-obfs"&&approved.Name=="obfs-local") &&
		!(name=="obfs-local"&&approved.Name=="simple-obfs") {
		return "",errors.New("trusted SIP003: link plugin differs from app-approved plugin")
	}
	if len(parts)>20{return "",errors.New("trusted SIP003: too many plugin options")}
	if approved.LocalOptions!="" {
		if len(parts)!=1||len(approved.LocalOptions)>2048||strings.ContainsAny(approved.LocalOptions,"\x00\r\n"){
			return "",errors.New("trusted SIP003: link conflicts with locally approved options")
		}
		return approved.LocalOptions,nil
	}
	if name!="v2ray-plugin"&&name!="obfs-local"&&name!="simple-obfs" {
		if len(parts)>1{return "",errors.New("trusted SIP003: third-party options must be local")}
		return "",nil
	}
	seen:=make(map[string]string)
	for _,part:=range parts[1:]{
		key,value,hasValue:=strings.Cut(part,"=")
		key=strings.ToLower(key)
		if key==""||len(value)>1024{return "",errors.New("trusted SIP003: invalid option")}
		if _,ok:=seen[key];ok{return "",errors.New("trusted SIP003: duplicate option")}
		if name=="v2ray-plugin" {
			switch key {
			case "tls":
				if hasValue{return "",errors.New("trusted SIP003: invalid TLS flag")}
			case "mode","host","path","mux":
				if !hasValue||value==""{return "",errors.New("trusted SIP003: missing option value")}
			default:
				return "",errors.New("trusted SIP003: unsupported v2ray-plugin option")
			}
		} else {
			if (key!="obfs" && key!="obfs-host")||!hasValue||value=="" {
				return "",errors.New("trusted SIP003: unsupported simple-obfs option")
			}
		}
		seen[key]=value
	}
	if name=="obfs-local"||name=="simple-obfs" {
		if seen["obfs"]!="http"&&seen["obfs"]!="tls" {
			return "",errors.New("trusted SIP003: simple-obfs requires http or tls")
		}
		if v:=seen["obfs-host"];v!=""{
			if _,err:=nodeEndpoint(v,"443");err!=nil {
				return "",errors.New("trusted SIP003: invalid obfs host")
			}
		}
	} else {
		if mode:=seen["mode"];mode!=""&&mode!="websocket"&&mode!="quic"{
			return "",errors.New("trusted SIP003: invalid mode")
		}
		if host:=seen["host"];host!=""{
			if _,err:=nodeEndpoint(host,"443");err!=nil {
				return "",errors.New("trusted SIP003: invalid plugin host")
			}
		}
		if path:=seen["path"];path!=""{
			u,err:=url.ParseRequestURI(path)
			if err!=nil||!strings.HasPrefix(path,"/")||strings.HasPrefix(path,"//")||
				u==nil||u.IsAbs()||u.Host!=""||u.RawQuery!=""||
				strings.ContainsAny(path,"?#\t"){
				return "",errors.New("trusted SIP003: invalid plugin path")
			}
		}
		if mux:=seen["mux"];mux!=""{
			v,err:=strconv.ParseUint(mux,10,8)
			if err!=nil||v>32{return "",errors.New("trusted SIP003: invalid mux")}
		}
	}
	return strings.Join(parts[1:],";"),nil
}
