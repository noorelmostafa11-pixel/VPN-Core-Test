//go:build linux || darwin || freebsd || openbsd

package core

import (
	"golang.zx2c4.com/wireguard/tun"
	"os"
)

// OpenTUNFile transfers ownership of an established descriptor to the core.
// On Android, pass a duplicate of the descriptor established by VpnService.
func OpenTUNFile(file *os.File, mtu int) (PacketDevice, error) {
	d, e := tun.CreateTUNFromFile(file, mtu)
	if e != nil {
		return nil, e
	}
	return wrapDevice(d), nil
}
