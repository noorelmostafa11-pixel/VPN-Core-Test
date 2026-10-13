package core

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// StartHTTP and StartMixed bind loopback only, just like StartSOCKS.
// Server listeners use a separately authenticated server configuration.
func (e *Engine) StartHTTP(address string) (net.Addr, error) {
	return e.startLocalProxy(address, false)
}
func (e *Engine) StartMixed(address string) (net.Addr, error) {
	return e.startLocalProxy(address, true)
}
func (e *Engine) startLocalProxy(address string, mixed bool) (net.Addr, error) {
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("LOCAL_LISTENER_REQUIRED")
	}
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	if !e.track(l) {
		return nil, net.ErrClosed
	}
	if !e.spawn(func() {
		defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if !e.acquire() {
				c.Close()
				continue
			}
			if !e.track(c) {
				e.release()
				return
			}
			if !e.spawn(func() {
				defer e.release()
				defer e.untrack(c)
				defer c.Close()
				c.SetDeadline(time.Now().Add(e.config.ConnectTimeout))
				reader := bufio.NewReaderSize(c, 4096)
				if mixed {
					prefix, err := reader.Peek(1)
					if err != nil {
						return
					}
					if prefix[0] == 5 {
						e.handleSOCKS(&bufferedConn{Conn: c, r: reader})
						return
					}
				}
				e.accepted.Add(1)
				e.handleHTTP(c, reader)
			}) {
				e.release()
				c.Close()
				return
			}
		}
	}) {
		l.Close()
		return nil, net.ErrClosed
	}
	e.emit(Event{Event: "ready"})
	return l.Addr(), nil
}

func httpError(c net.Conn, status int) {
	body := http.StatusText(status) + "\n"
	fmtResponse := http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Close: true}
	c.SetWriteDeadline(time.Now().Add(time.Second))
	fmtResponse.Write(c)
}

func (e *Engine) handleHTTP(c net.Conn, reader *bufio.Reader) {
	// Bound headers separately so an arbitrarily long header cannot allocate
	// memory until the connection deadline. Body bytes remain streaming.
	var header bytes.Buffer
	for header.Len() <= 32768 {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			httpError(c, 400)
			return
		}
		header.Write(line)
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
	}
	if header.Len() > 32768 {
		httpError(c, 431)
		return
	}
	parsedReader := bufio.NewReader(io.MultiReader(bytes.NewReader(header.Bytes()), reader))
	request, err := http.ReadRequest(parsedReader)
	if err != nil {
		httpError(c, 400)
		return
	}
	defer request.Body.Close()
	hostport := request.URL.Host
	if request.Method == "CONNECT" {
		hostport = request.Host
	}
	if hostport == "" || request.Method != "CONNECT" && request.URL.Scheme != "http" {
		httpError(c, 400)
		return
	}
	host, portText, err := net.SplitHostPort(hostport)
	if err != nil {
		if request.Method == "CONNECT" || strings.Contains(hostport, ":") {
			httpError(c, 400)
			return
		}
		host, portText = hostport, "80"
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || !hostValid(host) {
		httpError(c, 400)
		return
	}
	if request.Method == "CONNECT" && (request.ContentLength > 0 || len(request.TransferEncoding) > 0) {
		httpError(c, 400)
		return
	}
	id := e.next.Add(1)
	server, err := e.dialTCP(e.ctx, host, port)
	if err != nil {
		e.emit(dialFailure(id, err))
		httpError(c, 502)
		return
	}
	if !e.track(server) {
		return
	}
	defer e.untrack(server)
	defer server.Close()
	c.SetDeadline(time.Time{})
	if request.Method == "CONNECT" {
		if writeAll(c, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")) != nil {
			return
		}
		// Replay bytes prefetched along with the CONNECT header.
		e.relay(&bufferedConn{Conn: c, r: parsedReader}, server)
		return
	}
	for _, token := range strings.Split(request.Header.Get("Connection"), ",") {
		request.Header.Del(strings.TrimSpace(token))
	}
	for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		request.Header.Del(h)
	}
	request.RequestURI = ""
	request.Close = true
	request.Header.Set("Connection", "close")
	c.SetDeadline(time.Now().Add(e.config.IdleTimeout))
	server.SetDeadline(time.Now().Add(e.config.IdleTimeout))
	if err = request.Write(server); err != nil {
		return
	}
	response, err := http.ReadResponse(bufio.NewReader(server), request)
	if err != nil {
		httpError(c, 502)
		return
	}
	defer response.Body.Close()
	response.Close = true
	response.Header.Set("Connection", "close")
	c.SetDeadline(time.Now().Add(e.config.IdleTimeout))
	server.SetDeadline(time.Now().Add(e.config.IdleTimeout))
	response.Write(c)
}
