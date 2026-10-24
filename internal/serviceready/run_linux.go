//go:build linux

package serviceready

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// CAP_SYS_PTRACE permits read-only /proc proof of the more-privileged main
// daemon. All other active/permitted/bounding bits are removed on all Go threads.
// This is not a hostile-root boundary: no ptrace, signal, exec or cgroup mutation
// operation is exposed. CGO-linked runtimes fail closed on AllThreadsSyscall.
const ceiling = uint64(1 << 19)

func bounded(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errPolicy
	}
	return b, nil
}
func digestFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (64<<20)+1))
	if e != nil || n < 1 || n > 64<<20 {
		return "", errPolicy
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func restrict() error {
	b, e := bounded("/proc/sys/kernel/cap_last_cap", 64)
	if e != nil {
		return e
	}
	last, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil || last < 19 || last > 63 {
		return errPolicy
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); e != 0 {
		return e
	}
	for cap := 0; cap <= last; cap++ {
		if cap != 19 {
			if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(cap), 0); e != 0 {
				return e
			}
		}
	}
	h := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{{Effective: uint32(ceiling), Permitted: uint32(ceiling)}}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	return launch.ServiceCapabilities(ceiling)
}
func onePID(data []byte) (int, error) {
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0, unix.EAGAIN
	}
	p, e := strconv.Atoi(s)
	if e != nil || p <= 1 || strconv.Itoa(p) != s {
		return 0, errPolicy
	}
	return p, nil
}
func alive(fd int) error {
	p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, e := unix.Poll(p, 0)
	if e != nil {
		return e
	}
	if n != 0 {
		return errPolicy
	}
	return nil
}

// Capture an incarnation before connecting; pidfd liveness closes PID reuse
// between peer credentials and pre/post executable/argv/placement observations.
func mainProof(n launch.Manifest, pid int) error {
	root := "/proc/" + strconv.Itoa(pid)
	b, e := bounded(root+"/cgroup", 4096)
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(b)) != "0::"+strings.TrimPrefix(n.UnitRoot, "/sys/fs/cgroup")+"/node/control" {
		return errPolicy
	}
	sha, e := digestFile(root + "/exe")
	if e != nil {
		return e
	}
	if sha != n.Daemon.SHA256 {
		// The same-PID launcher moves into control just before exec. It
		// cannot pass readiness until the pinned ordinary image is present.
		return unix.EAGAIN
	}
	b, e = bounded(root+"/cmdline", 16384)
	if e != nil {
		return e
	}
	if !bytes.Equal(b, []byte(strings.Join(n.Arguments(), "\x00")+"\x00")) {
		return errPolicy
	}
	return nil
}
func snapshot(n launch.Manifest) error {
	for _, x := range []struct {
		name, sha string
		limit     int64
	}{{"backend.json", n.Backend.SHA256, 16384}, {"auth.json", n.Auth.SHA256, 65536}} {
		b, e := launch.ServiceFile(n.InputDir+"/"+x.name, x.limit)
		if e != nil {
			return e
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != x.sha {
			return errPolicy
		}
	}
	return nil
}
func peer(conn *net.UnixConn, pid int) error {
	raw, e := conn.SyscallConn()
	if e != nil {
		return e
	}
	var cred *unix.Ucred
	var cause error
	if e = raw.Control(func(fd uintptr) { cred, cause = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); e != nil {
		return e
	}
	if cause != nil {
		return cause
	}
	if cred == nil || cred.Pid != int32(pid) || cred.Uid != 0 || cred.Gid != 0 {
		return errPolicy
	}
	return nil
}
func probe(ctx context.Context, n launch.Manifest) error {
	b, e := bounded(n.UnitRoot+"/node/control/cgroup.procs", 4096)
	if e != nil {
		return e
	}
	pid, e := onePID(b)
	if e != nil {
		return e
	}
	fd, e := unix.PidfdOpen(pid, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if e = alive(fd); e != nil {
		return e
	}
	if e = mainProof(n, pid); e != nil {
		return e
	}
	if e = snapshot(n); e != nil {
		return e
	}
	path := n.StateDir + "/api.sock"
	before, e := os.Lstat(path)
	if e != nil {
		return e
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSocket == 0 || before.Mode().Perm() != 0600 || st.Uid != 0 || st.Gid != 0 {
		return errPolicy
	}
	// Reuse the anchored ownership walk for the private directory, not a token
	// or a caller-selected TCP address. ServiceFile needs a regular file, so its
	// already-pinned state directory is checked here through openat directory FDs.
	if e = privateState(n.StateDir); e != nil {
		return e
	}
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return e
	}
	defer conn.Close()
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return errPolicy
	}
	if e = peer(u, pid); e != nil {
		return e
	}
	after, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !os.SameFile(before, after) {
		return errPolicy
	}
	if e = requestHealth(ctx, conn); e != nil {
		return e
	}
	if e = mainProof(n, pid); e != nil {
		return e
	}
	return alive(fd)
}
func privateState(path string) error {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range parts {
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return e
		}
		fd = next
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil {
			unix.Close(fd)
			return e
		}
		if st.Uid != 0 || st.Mode&0022 != 0 || i == len(parts)-1 && st.Mode&0077 != 0 {
			unix.Close(fd)
			return errPolicy
		}
	}
	return unix.Close(fd)
}
func retryable(e error) bool {
	if errors.Is(e, unix.EAGAIN) || errors.Is(e, os.ErrNotExist) || errors.Is(e, unix.ECONNREFUSED) || errors.Is(e, unix.ESRCH) || errors.Is(e, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(e, &ne) && ne.Timeout()
}
func waitReady(ctx context.Context, check func(context.Context) error) error {
	for {
		attempt, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		e := check(attempt)
		cancel()
		if e == nil {
			return nil
		}
		if !retryable(e) {
			return e
		}
		t := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
func Run(path string) (ret error) {
	stage := "platform"
	defer func() {
		if ret != nil {
			ret = &failure{stage: stage}
		}
	}()
	if e := launch.SystemdService(); e != nil {
		return e
	}
	if e := launch.RejectServiceDescriptors(); e != nil {
		return e
	}
	stage = "manifest"
	b, e := launch.ServiceFile(path, 16384)
	if e != nil {
		return e
	}
	m, e := Decode(b)
	if e != nil {
		return e
	}
	self, e := digestFile("/proc/self/exe")
	if e != nil || self != m.Helper.SHA256 {
		return errPolicy
	}
	b, e = launch.PinnedServiceFile(m.NodeLaunch, 16384)
	if e != nil {
		return e
	}
	n, e := launch.Decode(b)
	if e != nil {
		return e
	}
	stage = "placement"
	if e = launch.ServicePlacement(n.UnitRoot + "/.control"); e != nil {
		return e
	}
	b, e = bounded(n.UnitRoot+"/.control/cgroup.procs", 4096)
	if e != nil {
		return e
	}
	pid, e := onePID(b)
	if e != nil || pid != os.Getpid() {
		return errPolicy
	}
	stage = "privileges"
	if e = restrict(); e != nil {
		return e
	}
	stage = "composition"
	b, e = launch.PinnedServiceFile(n.Backend, 16384)
	if e != nil {
		return e
	}
	var backend firecracker.Config
	if strictjson.Decode(b, &backend) != nil || n.CheckServiceBackend(backend) != nil || backend.IO == nil || backend.IO.Device != m.Device {
		return errPolicy
	}
	if e = launch.CheckServiceEnvelope(n.UnitRoot, m.Device, n.Parent, false, 0); e != nil {
		return e
	}
	stage = "waiting"
	ctx, cancel := context.WithTimeout(context.Background(), WaitSeconds*time.Second)
	defer cancel()
	return waitReady(ctx, func(ctx context.Context) error { return probe(ctx, n) })
}
