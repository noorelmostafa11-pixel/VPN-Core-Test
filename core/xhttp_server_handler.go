package core

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func xServerRequest(r *http.Request, t *ServerTransportConfig) (kind, id string, seq uint64, ok bool) {
	if !serverHostMatches(r.Host, t.Host) || len(r.Header.Values("Content-Encoding")) > 1 || r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		return
	}
	for _, key := range []string{"X-Session", "X-Seq"} {
		if len(r.Header.Values(key)) != 0 {
			return
		}
	}
	for _, key := range []string{"x_session", "x_seq"} {
		if r.URL.Query().Has(key) {
			return
		}
		if _, err := r.Cookie(key); err == nil {
			return
		}
	}
	if r.URL.Path == t.Path {
		return "single", "", 0, r.Method == t.Method && t.Mode != "packet-up"
	}
	if t.Mode == "stream-one" || !strings.HasPrefix(r.URL.Path, t.Path) {
		return
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, t.Path), "/"), "/")
	if len(parts) < 1 || len(parts) > 2 || len(parts[0]) == 0 || len(parts[0]) > 128 {
		return
	}
	id = parts[0]
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return "", "", 0, false
		}
	}
	if r.Method == "GET" {
		return "down", id, 0, len(parts) == 1 && r.ContentLength == 0 && len(r.TransferEncoding) == 0
	}
	if r.Method != t.Method {
		return "", "", 0, false
	}
	if len(parts) == 1 {
		return "upload", id, 0, t.Mode == "auto" || t.Mode == "stream-up"
	}
	if t.Mode != "auto" && t.Mode != "packet-up" || len(parts[1]) == 0 || len(parts[1]) > 20 {
		return "", "", 0, false
	}
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return "", "", 0, false
		}
	}
	seq, err := strconv.ParseUint(parts[1], 10, 64)
	return "packet", id, seq, err == nil && seq != ^uint64(0)
}

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
	if !e.acquire() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer e.release()
	controller := http.NewResponseController(w)
	if r.ProtoMajor == 1 && controller.EnableFullDuplex() != nil {
		return
	}
	remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
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
	xServerHeaders(w)
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
