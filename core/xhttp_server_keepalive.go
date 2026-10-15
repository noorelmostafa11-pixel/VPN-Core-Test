package core

import (
	"context"
	"io"
	"time"
)

func (s *xServerSession) writeUploadPadding(c *serverHTTP2Conn, data []byte, timeout time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.uploadErr != nil {
		return nil
	}
	deadline := time.Now().Add(min(timeout, 5*time.Second))
	if !s.deadline.IsZero() && s.deadline.Before(deadline) {
		deadline = s.deadline
	}
	if err := c.SetWriteDeadline(deadline); err != nil {
		return err
	}
	n, err := c.Write(data)
	if n != len(data) && err == nil {
		err = io.ErrShortWrite
	}
	if reset := c.SetWriteDeadline(s.deadline); err == nil {
		err = reset
	}
	return err
}

func (e *Engine) waitXHTTPUpload(c *serverHTTP2Conn, s *xServerSession, done <-chan struct{}, x XHTTPServerOptions) {
	var timer *time.Timer
	var ticks <-chan time.Time
	var data []byte
	r := x.ScStreamUpServerSecs
	if r != nil && r.To > 0 && (c.request.Header.Get("Referer") != "" || x.XPaddingObfsMode && x.paddingRequired) {
		data = make([]byte, x.paddingRange().Hi)
		for i := range data {
			data[i] = 'X'
		}
		timer = time.NewTimer(0)
		ticks = timer.C
		defer timer.Stop()
		// Cancel blocked writes, and join the callback before the HTTP writer dies.
		joined := make(chan struct{})
		stop := context.AfterFunc(s.ctx, func() {
			c.Close()
			close(joined)
		})
		defer func() {
			if !stop() {
				<-joined
			}
		}()
	}
	for {
		select {
		case <-done:
			return
		case <-c.request.Context().Done():
			s.Close()
			return
		case <-s.ctx.Done():
			return
		case <-ticks:
			if err := s.writeUploadPadding(c, data[:x.paddingRange().choose()], e.config.ConnectTimeout); err != nil {
				s.Close()
				return
			}
			timer.Reset(time.Duration((intRange{r.From, r.To}).choose()) * time.Second)
		}
	}
}
