//go:build !linux && !darwin && !freebsd && !openbsd

package core

import "errors"

func OpenTUNFD(fd, mtu int) (PacketDevice, error) {
	return nil, errors.New("TUN_FD_UNAVAILABLE: use OpenTUN or PacketDevice")
}
