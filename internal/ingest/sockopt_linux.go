//go:build linux

package ingest

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func reusePortControl(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

// setRecvBuffer tries SO_RCVBUF (capped by net.core.rmem_max), then
// SO_RCVBUFFORCE (needs CAP_NET_ADMIN). Returns the effective size; Linux
// reports double the requested value to account for bookkeeping, so we halve it.
func setRecvBuffer(c *net.UDPConn, want int) int {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0
	}
	got := 0
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, want)
		v, _ := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if v/2 < want {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, want)
			v, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		}
		got = v / 2
	})
	return got
}
