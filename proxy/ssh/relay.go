package ssh

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	sshlib "golang.org/x/crypto/ssh"
)

// Cancellation closes the owned transport, then joins the callback. A channel
// timeout never sets a deadline on a server's shared SSH socket.
func closeOnCancel(ctx context.Context, closeConn func()) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		closeConn()
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

type activity struct {
	start time.Time
	last  atomic.Int64
}

func (a *activity) Update()             { a.last.Store(time.Since(a.start).Nanoseconds()) }
func (a *activity) idle() time.Duration { return time.Since(a.start.Add(time.Duration(a.last.Load()))) }

// relay owns and joins both copy loops, including blocked pipe/socket writes.
// EOF is half-close: delayed responses and server-first traffic remain valid.
func relay(ctx context.Context, channel sshlib.Channel, requests <-chan *sshlib.Request, link *transport.Link, limits policy.Timeout, inbound bool, abortTransport func()) error {
	a := &activity{start: time.Now()}
	a.Update()
	timeout := limits.ConnectionIdle
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	type result struct {
		toChannel bool
		err       error
	}
	results := make(chan result, 2)
	requestsDone, stderrDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(requestsDone); sshlib.DiscardRequests(requests) }()
	go func() { defer close(stderrDone); io.Copy(io.Discard, channel.Stderr()) }()
	go func() {
		err := buf.Copy(link.Reader, buf.NewWriter(channel), buf.UpdateActivity(a))
		if err == nil {
			err = channel.CloseWrite()
		}
		results <- result{true, err}
	}()
	go func() {
		err := buf.Copy(buf.NewReader(channel), link.Writer, buf.UpdateActivity(a))
		if err == nil {
			err = common.Close(link.Writer)
		}
		results <- result{false, err}
	}()
	remaining := 2
	var failure error
	for remaining > 0 && failure == nil {
		select {
		case <-ctx.Done():
			failure = ctx.Err()
		case <-timer.C:
			left := timeout - a.idle()
			if left <= 0 || timeout <= 0 {
				failure = errors.New("SSH forwarding idle timeout")
			} else {
				timer.Reset(left)
			}
		case result := <-results:
			remaining--
			failure = result.err
			if result.toChannel != inbound {
				timeout = limits.DownlinkOnly
			} else {
				timeout = limits.UplinkOnly
			}
			// Start the half-close grace period at EOF, even if the preceding
			// transfer was idle. Subsequent data extends the same period.
			a.Update()
			timer.Reset(timeout)
		}
	}
	if failure != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
	joined := make(chan struct{})
	go func() {
		channel.Close()
		for remaining > 0 {
			<-results
			remaining--
		}
		<-requestsDone
		<-stderrDone
		close(joined)
	}()
	// A cooperative channel close leaves sibling channels alive. If the
	// peer stops processing SSH close/control messages, only closing that
	// peer's entire transport can unblock x/crypto's channel workers.
	grace := time.NewTimer(limits.Handshake)
	defer grace.Stop()
	select {
	case <-joined:
	case <-grace.C:
		abortTransport()
		<-joined
		if failure == nil {
			failure = errors.New("SSH peer did not complete channel close")
		}
	}
	return failure
}
