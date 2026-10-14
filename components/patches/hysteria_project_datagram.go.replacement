package quic

import (
	"context"
	"errors"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
)

// ProjectSendDatagramContext keeps packet ownership synchronous and permits a
// session deadline/close to interrupt backpressure without closing other flows.
func (c *Conn) ProjectSendDatagramContext(ctx context.Context, payload []byte) error {
	if !c.supportsDatagrams() {
		return errors.New("datagram support disabled")
	}
	f := &wire.DatagramFrame{DataLenPresent: true}
	limit := min(f.MaxDataLen(c.peerMaxDatagramFrameSize(), c.version), protocol.ByteCount(c.maxPayloadSizeEstimate.Load()))
	if protocol.ByteCount(len(payload)) > limit {
		return &DatagramTooLargeError{MaxDatagramPayloadSize: int64(limit)}
	}
	f.Data = append([]byte(nil), payload...)
	h := c.datagramQueue
	h.sendMx.Lock()
	for {
		if err := ctx.Err(); err != nil {
			h.sendMx.Unlock()
			return err
		}
		select {
		case <-h.closed:
			h.sendMx.Unlock()
			return h.closeErr
		default:
		}
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			h.sendQueue.PushBack(f)
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		select {
		case <-h.sent:
		default:
		}
		h.sendMx.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.closed:
			return h.closeErr
		case <-h.sent:
		}
		h.sendMx.Lock()
	}
}
