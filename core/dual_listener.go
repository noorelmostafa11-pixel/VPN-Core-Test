package core

import (
	"errors"
	"net"
	"strconv"
)

// listenTCPUDP owns both sockets before returning. TCP and UDP use separate
// automatic-port allocators; a TCP-selected port can be occupied or excluded
// for UDP. Only automatic ports may be replaced, and failed binds start no workers.
func (e *Engine) listenTCPUDP(address string, listenTCP func(string, string) (net.Listener, error), listenUDP func(string, string) (net.PacketConn, error)) (net.Listener, net.PacketConn, error) {
	_, port, _ := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	attempts := 1
	if address == "" || (portErr == nil && n == 0) {
		attempts = 8
	}
	var err error
	for i := 0; i < attempts; i++ {
		if e.ctx.Err() != nil {
			return nil, nil, net.ErrClosed
		}
		listener, bindErr := listenTCP("tcp", address)
		if bindErr != nil {
			return nil, nil, bindErr
		}
		if !e.track(listener) {
			return nil, nil, net.ErrClosed
		}
		packet, bindErr := listenUDP("udp", listener.Addr().String())
		if bindErr == nil {
			if e.track(packet) {
				return listener, packet, nil
			}
			bindErr = net.ErrClosed
		}
		listener.Close()
		e.untrack(listener)
		err = bindErr
		if errors.Is(err, net.ErrClosed) {
			break
		}
	}
	return nil, nil, err
}
