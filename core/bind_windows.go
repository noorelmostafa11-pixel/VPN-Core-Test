//go:build windows

package core

import (
	"context"
	"golang.org/x/sys/windows"
	"math/bits"
	"net"
	"unsafe"
)

// Bound upstream sockets cannot be captured by the tunnel's own routes.
func BindInterface(name string) (func(context.Context, int64) error, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	index := iface.Index
	return func(ctx context.Context, fd int64) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// An IPv6 option can succeed on an IPv4 Windows socket, and an
		// unbound socket has no sockname. Read the actual protocol family.
		var info windows.WSAProtocolInfo
		size := int32(unsafe.Sizeof(info))
		if err := windows.Getsockopt(windows.Handle(fd), windows.SOL_SOCKET, 0x2005, (*byte)(unsafe.Pointer(&info)), &size); err != nil {
			return err
		}
		if info.AddressFamily == windows.AF_INET6 {
			return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31, index)
		}
		return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(uint32(index))))
	}, nil
}
