//go:build linux

package core

// The pinned Linux driver reports bytes written (including its virtio header),
// while the other native drivers report packet counts. A successful SYN-ACK
// must not be mistaken for a short write and shut down the whole tunnel.
func nativeWriteComplete(n, size, batch int) bool {
	if batch > 1 {
		size += 10 // virtio_net_hdr used by the pinned Linux device
	}
	return n == size
}
