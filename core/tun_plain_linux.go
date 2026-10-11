//go:build linux

package core

import (
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// The embedded packet stack consumes complete IP packets. Keep the kernel from
// passing partial-checksum or super-packet offloads across this device boundary.
func configurePacketDevice(d tun.Device) error {
	if d.BatchSize() > 1 {
		return unix.IoctlSetInt(int(d.File().Fd()), unix.TUNSETOFFLOAD, 0)
	}
	return nil
}
