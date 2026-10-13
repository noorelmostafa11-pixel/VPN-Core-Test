//go:build linux || darwin || freebsd || openbsd

package core

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

// OpenTUNFD duplicates an app-owned descriptor; closing the engine leaves the
// app's original descriptor valid. Configure socket protection before routing.
func OpenTUNFD(fd, mtu int) (PacketDevice, error) {
	if fd < 3 {
		return nil, errors.New("TUN_FD_INVALID")
	}
	dup, e := unix.Dup(fd)
	if e != nil {
		return nil, e
	}
	unix.CloseOnExec(dup)
	file := os.NewFile(uintptr(dup), "vpn-tun")
	d, e := OpenTUNFile(file, mtu)
	if e != nil {
		file.Close()
	}
	return d, e
}
