//go:build !linux && !darwin

package nodecontrol

import (
	"errors"
	"net"
)

func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("operator peer credentials unsupported")
}
