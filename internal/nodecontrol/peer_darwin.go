//go:build darwin

package nodecontrol

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
)

func peerUID(c *net.UnixConn) (uint32, error) {
	r, e := c.SyscallConn()
	if e != nil {
		return 0, e
	}
	var uid uint32
	var inner error
	e = r.Control(func(fd uintptr) {
		u, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		inner = err
		if err == nil {
			// XUCRED_VERSION is0 in Apple bsd/sys/ucred.h.
			if u.Version != 0 {
				inner = errors.New("invalid peer credentials")
			} else {
				uid = u.Uid
			}
		}
	})
	if e != nil {
		return 0, e
	}
	return uid, inner
}
