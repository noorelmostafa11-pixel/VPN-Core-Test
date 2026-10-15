package core

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

func xServerHeaders(w http.ResponseWriter, x XHTTPServerOptions) {
	if !x.NoSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.Header().Set("Content-Encoding", "identity")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	xServerResponsePadding(w, x)
}

func (e *Engine) serveXHTTP(w http.ResponseWriter, r *http.Request, spec serverSpec, sessions *xServerSessions) {
	if !e.ownHTTPHandler() {
		return
	}
	defer e.workers.Done()
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	cookies := r.Cookies()
	kind, id, seq, valid := xServerClassifyRequest(r, spec.transport, query, cookies)
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
	x := spec.transport.xhttpMetadata()
	xServerHeaders(w, x)
	if !xServerValidPadding(r, query, cookies, x) {
		xServerStatus(c, http.StatusBadRequest)
		return
	}
	if kind == "down" && r.ProtoMajor == 3 {
		// HTTP3 represents an absent Content-Length as -1, including GETs.
		// Validate their actual FIN before allocating a split session.
		var first [1]byte
		if n, err := c.Read(first[:]); n != 0 || err != io.EOF {
			xServerStatus(c, http.StatusNotFound)
			return
		}
	}
	var packet xServerPacketPlan
	if kind == "packet" {
		var status int
		packet, status = xServerPlanPacket(r, spec.transport.xhttpMetadata())
		if status != 0 {
			xServerStatus(c, status)
			return
		}
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
		e.receiveXHTTPPacket(c, session, seq, packet)
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
