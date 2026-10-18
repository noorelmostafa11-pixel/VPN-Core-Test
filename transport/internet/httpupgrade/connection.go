package httpupgrade

import (
	"io"
	"net"
)

type connection struct {
	net.Conn
	remoteAddr net.Addr
	reader     io.Reader
}

func (c *connection) Read(p []byte) (int, error) {
	if c.reader != nil {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

func newConnection(conn net.Conn, remoteAddr net.Addr) *connection {
	return &connection{
		Conn:       conn,
		remoteAddr: remoteAddr,
	}
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}
