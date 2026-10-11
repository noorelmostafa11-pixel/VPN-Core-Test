//go:build !linux && (windows || darwin || freebsd || openbsd)

package core

import "golang.zx2c4.com/wireguard/tun"

func configurePacketDevice(d tun.Device) error { return nil }
