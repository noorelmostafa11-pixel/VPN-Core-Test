// Project-owned bounded record primitives used by the legacy transport adapter.
package tls
import "errors"
func(c *Conn) ProjectAdvanceInbound(){c.in.Lock();defer c.in.Unlock();c.in.incSeq()}
func(c *Conn) ProjectAdvanceOutbound(){c.out.Lock();defer c.out.Unlock();c.out.incSeq()}
func(c *Conn) ProjectDecodeRecord(record []byte)([]byte,uint8,error){c.in.Lock();defer c.in.Unlock();if c.vers!=VersionTLS13||len(record)<5||len(record)>18437||int(record[3])*256+int(record[4])+5!=len(record){return nil,0,errors.New("record bounds")};data,kind,err:=c.in.decrypt(record);return data,uint8(kind),err}
