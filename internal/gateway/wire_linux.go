//go:build linux

package gateway

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const (
	opConnect byte = 1 + iota
	opRelease
	opConnected
	opUnavailable
	opPolicy
	opReady
	opHeartbeat
)

// A fixed24-byte private capability protocol, not JSON/paths/argv/syscalls.
// Only a root-created inherited socketpair is used, never a named broker API.
type frame struct {
	op             byte
	request, lease uint64
}

func (f frame) encode() []byte {
	b := make([]byte, 24)
	copy(b, "XBGC")
	b[4] = 1
	b[5] = f.op
	binary.LittleEndian.PutUint64(b[8:], f.request)
	binary.LittleEndian.PutUint64(b[16:], f.lease)
	return b
}
func decodeFrame(b []byte) (frame, error) {
	if len(b) != 24 || string(b[:4]) != "XBGC" || b[4] != 1 || b[6] != 0 || b[7] != 0 || b[5] < opConnect || b[5] > opHeartbeat {
		return frame{}, errors.New("invalid gateway control frame")
	}
	return frame{op: b[5], request: binary.LittleEndian.Uint64(b[8:]), lease: binary.LittleEndian.Uint64(b[16:])}, nil
}
func packetPair() (parent, child *net.UnixConn, err error) {
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, nil, e
	}
	a := os.NewFile(uintptr(fds[0]), "gateway-control")
	b := os.NewFile(uintptr(fds[1]), "gateway-child-control")
	defer a.Close()
	defer b.Close()
	p, e := net.FileConn(a)
	if e != nil {
		return nil, nil, e
	}
	c, e := net.FileConn(b)
	if e != nil {
		p.Close()
		return nil, nil, e
	}
	return p.(*net.UnixConn), c.(*net.UnixConn), nil
}
func readFrame(c *net.UnixConn) (frame, int, error) {
	data := make([]byte, 25)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, on, flags, _, e := c.ReadMsgUnix(data, oob)
	if e != nil {
		return frame{}, -1, e
	}
	var fds []int
	msgs, parseErr := unix.ParseSocketControlMessage(oob[:on])
	for _, m := range msgs {
		rights, e := unix.ParseUnixRights(&m)
		if e != nil {
			parseErr = e
			continue
		}
		for _, fd := range rights {
			unix.CloseOnExec(fd)
		}
		fds = append(fds, rights...)
	}
	f, err := decodeFrame(data[:n])
	if parseErr != nil || err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(fds) > 1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return frame{}, -1, errors.New("invalid gateway control packet")
	}
	fd := -1
	if len(fds) == 1 {
		fd = fds[0]
	}
	return f, fd, nil
}
func writeFrame(c *net.UnixConn, f frame, fd int) error {
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	n, _, e := c.WriteMsgUnix(f.encode(), oob, nil)
	if e != nil {
		return e
	}
	if n != 24 {
		return io.ErrShortWrite
	}
	return nil
}

const snapshotSeals = unix.F_SEAL_SEAL | unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK

func sealedSnapshot(s Snapshot) (*os.File, error) {
	b, e := json.Marshal(s)
	if e != nil || len(b) == 0 || len(b) > MaxSnapshotBytes {
		return nil, errors.New("invalid gateway snapshot size")
	}
	fd, e := unix.MemfdCreate("xandbox-gateway-policy", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "gateway-policy")
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return nil, e
	}
	if _, e = f.Write(b); e != nil {
		return nil, e
	}
	if _, e = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, snapshotSeals); e != nil {
		return nil, e
	}
	// Reopen read-only: seals alone do not change the descriptor's access mode.
	ro, e := unix.Open("/proc/self/fd/"+itoaFD(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(ro), "gateway-policy-readonly"), nil
}
func itoaFD(fd int) string { // No path from a control packet is ever used.
	if fd == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for fd > 0 {
		i--
		b[i] = byte('0' + fd%10)
		fd /= 10
	}
	return string(b[i:])
}
func readSnapshot(f *os.File) (Snapshot, error) {
	var zero Snapshot
	var st unix.Stat_t
	if e := unix.Fstat(int(f.Fd()), &st); e != nil {
		return zero, e
	}
	seals, e := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if e != nil || seals != snapshotSeals || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Uid != 0 || st.Size <= 0 || st.Size > MaxSnapshotBytes {
		return zero, errors.New("sealed root policy descriptor required")
	}
	flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return zero, errors.New("read-only policy descriptor required")
	}
	b := make([]byte, st.Size)
	if _, e = f.ReadAt(b, 0); e != nil {
		return zero, e
	}
	var s Snapshot
	if strictjson.Decode(b, &s) != nil {
		return zero, errors.New("invalid sealed gateway policy")
	}
	return s, nil
}
