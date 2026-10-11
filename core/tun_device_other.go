//go:build !linux && !windows && !darwin && !freebsd && !openbsd

package core

import "errors"

func OpenTUN(name string, mtu int) (PacketDevice, string, error) {
	return nil, "", errors.New("TUN_HOST_DEVICE_REQUIRED: supply PacketDevice")
}
