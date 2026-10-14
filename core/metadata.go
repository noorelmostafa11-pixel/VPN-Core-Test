package core

import (
	utls "github.com/refraction-networking/utls"
	"net"
)

func connectionMeta(c net.Conn) (string, string) {
	switch c := c.(type) {
	case *utls.UConn:
		s := c.ConnectionState()
		v := "TLS1.2"
		if s.Version == 0x304 {
			v = "TLS1.3"
		}
		return v, s.NegotiatedProtocol
	case *protocolConn:
		return connectionMeta(c.Conn)
	case *ownedConn:
		return connectionMeta(c.Conn)
	case *codecConn:
		return connectionMeta(c.Conn)
	case *wsConn:
		return connectionMeta(c.Conn)
	case *bufferedConn:
		return connectionMeta(c.Conn)
	case *rawHTTPConn:
		return connectionMeta(c.Conn)
	case *directConn:
		return connectionMeta(c.Conn)
	case *vlessEncryptionConn:
		return connectionMeta(c.Conn)
	case *encryptionDirectConn:
		return connectionMeta(c.Conn)
	case *legacyXTLS:
		return connectionMeta(c.tls)
	case *queueConn:
		if c.metaConn != nil {
			return connectionMeta(c.metaConn)
		}
		v := ""
		if c.version == 0x303 {
			v = "TLS1.2"
		} else if c.version == 0x304 {
			v = "TLS1.3"
		}
		return v, c.alpn
	}
	return "", ""
}
