package core

import "runtime"

// Apple sockets default to a 9216-byte UDP send space. Raise only this socket's
// bounded buffers so reconstructed UDP payloads fit; never change system sysctl.
func configureDatagramBuffers(conn any) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		return
	}
	if c, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		c.SetReadBuffer(262144)
	}
	if c, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		c.SetWriteBuffer(262144)
	}
}
