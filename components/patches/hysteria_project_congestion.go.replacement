package client

import (
	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/quic-go"
)

// ProjectUseBrutal shares the pinned controller with the v3 wire adapter.
func ProjectUseBrutal(conn *quic.Conn, bytesPerSecond uint64) {
	congestion.UseBrutal(conn, bytesPerSecond, false)
}
