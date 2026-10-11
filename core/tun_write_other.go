//go:build windows || darwin || freebsd || openbsd

package core

func nativeWriteComplete(n, size, batch int) bool { return n == 1 }
