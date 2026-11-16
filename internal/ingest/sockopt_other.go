//go:build !linux

package ingest

import (
	"net"
	"syscall"
)

// On non-Linux platforms we use one socket per address (no SO_REUSEPORT
// load-spreading) and the portable SetReadBuffer.
func reusePortControl(_, _ string, _ syscall.RawConn) error { return nil }

func setRecvBuffer(c *net.UDPConn, want int) int {
	if err := c.SetReadBuffer(want); err != nil {
		return 0
	}
	return want
}
