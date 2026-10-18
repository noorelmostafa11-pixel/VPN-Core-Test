package serial

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "github.com/xtls/xray-core/infra/conf"
)

// Explicit versioned JSON node-list format; full strict per-node validation
// is shared with original single-node import, never with a generic JSON config.
func DecodeNodeListJSONConfig(reader io.Reader) (*conf.Config,error) {
 data,err:=io.ReadAll(io.LimitReader(reader,maxSubscriptionBytes+1))
 if err!=nil || len(data)>maxSubscriptionBytes{return nil,errors.New("node list: unreadable or oversized input")}
 data=bytes.TrimSpace(data)
 if len(data)>0 && data[0]=='{' {
  data,err=validatedNodeListEnvelope(data)
  if err!=nil{return nil,err}
 }
 if len(data)==0 || data[0]!='['{return nil,errors.New("node list: expected array")}
 var nodes []json.RawMessage
 if err:=json.Unmarshal(data,&nodes);err!=nil || len(nodes)==0 || len(nodes)>maxSubscriptionNodes {
  return nil,errors.New("node list: invalid array or node count")
 }
 result:=&conf.Config{OutboundConfigs:make([]conf.OutboundDetourConfig,0,len(nodes))}
 for i,raw:=range nodes{
  if len(raw)>conf.MaxNodeURIBytes{return nil,fmt.Errorf("node list: oversized description %d",i+1)}
  out,err:=conf.ParseNodeJSON(raw)
  if err!=nil{return nil,fmt.Errorf("node list: invalid description %d",i+1)}
  out.Tag=fmt.Sprintf("node-list-%03d",i+1)
  result.OutboundConfigs=append(result.OutboundConfigs,*out)
 }
 return result,nil
}
