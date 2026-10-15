package core

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func xServerHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Content-Encoding", "identity")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Padding", strings.Repeat("X", 100))
}

func (e *Engine) serveXHTTP(w http.ResponseWriter, r *http.Request, spec serverSpec, sessions *xServerSessions) {
	if !e.ownHTTPHandler() {
		return
	}
	defer e.workers.Done()
	kind, id, seq, valid := xServerRequest(r, spec.transport)
	if !valid {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// HTTP3 reserves request admission before reading its HEADERS frame.
	if r.ProtoMajor != 3 {
		if !e.acquire() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer e.release()
	}
	controller := http.NewResponseController(w)
	if r.ProtoMajor == 1 && controller.EnableFullDuplex() != nil {
		return
	}
	var remote net.Addr
	var err error
	if r.ProtoMajor == 3 {
		remote, err = net.ResolveUDPAddr("udp", r.RemoteAddr)
	} else {
		remote, err = net.ResolveTCPAddr("tcp", r.RemoteAddr)
	}
	if err != nil {
		return
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	c := &serverHTTP2Conn{request: r, writer: w, controller: controller, local: local, remote: remote}
	if !e.track(c) {
		return
	}
	defer e.untrack(c)
	defer c.Close()
	if c.SetDeadline(time.Now().Add(e.config.ConnectTimeout)) != nil {
		return
	}
	xServerHeaders(w)
	if kind == "down" && r.ProtoMajor == 3 {
		// HTTP3 represents an absent Content-Length as -1, including GETs.
		// Validate their actual FIN before allocating a split session.
		var first [1]byte
		if n, err := c.Read(first[:]); n != 0 || err != io.EOF {
			xServerStatus(c, http.StatusNotFound)
			return
		}
	}
	if kind == "packet" && r.ContentLength > xServerPostLimit {
		xServerStatus(c, http.StatusRequestEntityTooLarge)
		return
	}
	var session *xServerSession
	if id != "" {
		session, err = sessions.session(id)
		if err != nil {
			xServerStatus(c, http.StatusServiceUnavailable)
			return
		}
	}
	if kind == "packet" {
		e.receiveXHTTPPost(c, session, seq)
		return
	}
	if kind == "upload" {
		done, err := session.attachUpload(c)
		if err != nil {
			xServerStatus(c, http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusOK)
		if controller.Flush() != nil {
			session.Close()
			return
		}
		select {
		case <-done:
		case <-r.Context().Done():
			session.Close()
		case <-session.ctx.Done():
		}
		return
	}
	conn := net.Conn(c)
	if kind == "down" {
		// The validated GET has no upload body. Its response must drain at EOF.
		c.readEnded.Store(true)
		if !session.attachDown(c) {
			xServerStatus(c, http.StatusConflict)
			return
		}
		defer session.Close()
		stop := context.AfterFunc(r.Context(), func() { session.Close() })
		defer stop()
		conn = &xServerSplitConn{serverHTTP2Conn: c, session: session}
	}
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		return
	}
	deadline := time.Now().Add(e.config.ConnectTimeout)
	if conn.SetDeadline(deadline) != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	base := conn
	stop := context.AfterFunc(e.ctx, func() { cancel(); base.Close() })
	defer stop()
	if spec.encryption != nil {
		encrypted, err := spec.encryption.handshake(ctx, conn, deadline)
		if err != nil {
			return
		}
		conn = encrypted
	}
	e.serveServerContext(ctx, conn, spec)
}

func xServerStatus(c *serverHTTP2Conn, status int) {
	// Flush a finite response before interrupting any incomplete upload body.
	c.writer.Header().Set("Content-Length", "0")
	c.writer.WriteHeader(status)
	c.controller.Flush()
	c.CloseWrite()
}

func (e *Engine) receiveXHTTPPost(c *serverHTTP2Conn, session *xServerSession, seq uint64) {
	if c.request.ContentLength > xServerPostLimit {
		xServerStatus(c, http.StatusRequestEntityTooLarge)
		return
	}
	cost := xServerPostLimit + 1
	if c.request.ContentLength >= 0 {
		cost = int(c.request.ContentLength) + 1
	}
	if !session.manager.reserve(cost) {
		xServerStatus(c, http.StatusServiceUnavailable)
		return
	}
	owned := true
	defer func() {
		if owned {
			session.manager.buffered.Add(-int64(cost))
		}
	}()
	body := make([]byte, cost)
	n, err := io.ReadFull(c, body)
	if n > xServerPostLimit {
		xServerStatus(c, http.StatusRequestEntityTooLarge)
		return
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF || c.request.ContentLength >= 0 && int64(n) != c.request.ContentLength {
		xServerStatus(c, http.StatusBadRequest)
		return
	}
	if session.push(seq, xServerPacket{body: body[:n], cost: cost}) != nil {
		xServerStatus(c, http.StatusConflict)
		return
	}
	owned = false
	xServerStatus(c, http.StatusOK)
}
