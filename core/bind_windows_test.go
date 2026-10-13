//go:build windows

package core

import (
	"context"
	"golang.org/x/sys/windows"
	"net"
	"testing"
)

func TestBindInterfaceUnboundSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		hook, err := BindInterface(iface.Name)
		if err != nil {
			t.Fatal(err)
		}
		fd, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
		if err != nil {
			t.Fatal(err)
		}
		v6, v6err := windows.GetsockoptInt(fd, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
		err = hook(context.Background(), int64(fd))
		windows.Closesocket(fd)
		if err != nil {
			t.Fatalf("interface %s index=%d IPv6Only=%d probe=%v: %v", iface.Name, iface.Index, v6, v6err, err)
		}
	}
}
