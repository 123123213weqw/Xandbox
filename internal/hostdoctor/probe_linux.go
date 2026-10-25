//go:build linux

package hostdoctor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var errObservation = errors.New("host prerequisite observation unavailable")
var errFilesystem = errors.New("unexpected host filesystem")

func trustedDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errObservation
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		var s unix.Stat_t
		if unix.Fstat(fd, &s) != nil || s.Uid != 0 || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, errObservation
		}
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || s.Uid != 0 || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Mode&0022 != 0 {
		unix.Close(fd)
		return nil, errObservation
	}
	return os.NewFile(uintptr(fd), "doctor-directory"), nil
}

func filesystem(fd int, want int64) error {
	var s unix.Statfs_t
	if e := unix.Fstatfs(fd, &s); e != nil {
		return e
	}
	if int64(s.Type) != want {
		return errFilesystem
	}
	return nil
}

func boundedRead(f *os.File, limit int64) ([]byte, error) {
	if limit < 1 || limit > 4096 {
		return nil, errObservation
	}
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() {
		return nil, errObservation
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errObservation
	}
	return b, nil
}

func readKernelFile(dir *os.File, name string, fs int64, limit int64) ([]byte, error) {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "doctor-kernel-observation")
	defer f.Close()
	if e = filesystem(fd, fs); e != nil {
		return nil, e
	}
	return boundedRead(f, limit)
}

var controllerName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func parseControllers(raw []byte) ([]string, error) {
	if len(raw) > 4096 || bytes.ContainsAny(raw, "\r\x00") || len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		return nil, errObservation
	}
	seen := map[string]bool{}
	for _, name := range strings.Fields(string(raw)) {
		if !controllerName.MatchString(name) || seen[name] {
			return nil, errObservation
		}
		seen[name] = true
	}
	missing := []string{}
	for _, name := range []string{"cpu", "io", "memory", "pids"} {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	return missing, nil
}

var managerVersion = regexp.MustCompile(`^([1-9][0-9]{0,3})([.~-][0-9A-Za-z.+:~_-]+)?\n?$`)

func parseManagerVersion(raw []byte) (int, error) {
	if len(raw) > 256 {
		return 0, errObservation
	}
	m := managerVersion.FindSubmatch(raw)
	if m == nil {
		return 0, errObservation
	}
	n, e := strconv.Atoi(string(m[1]))
	if e != nil {
		return 0, errObservation
	}
	return n, nil
}

// Query the RUNNING system manager, not the installed systemctl package version.
// No unit, host, user manager, environment-selected command or mutation is used.
func managerArgs() []string {
	return []string{"--system", "--no-pager", "--no-ask-password", "show", "--property=Version", "--value"}
}

func managerEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER="}
}

type limitedBuffer struct {
	data  []byte
	limit int
}

func (b *limitedBuffer) Len() int      { return len(b.data) }
func (b *limitedBuffer) Bytes() []byte { return b.data }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errObservation
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func runQuery(cmd *exec.Cmd) ([]byte, error) {
	out, errout := &limitedBuffer{limit: 1024}, &limitedBuffer{limit: 1024}
	cmd.Stdout, cmd.Stderr = out, errout
	cmd.WaitDelay = 100 * time.Millisecond
	if e := cmd.Run(); e != nil || errout.Len() != 0 {
		return nil, errObservation
	}
	return out.Bytes(), nil
}

func runningManagerVersion(ctx context.Context) (int, error) {
	dir, e := trustedDirectory("/usr/bin")
	if e != nil {
		return 0, e
	}
	defer dir.Close()
	fd, e := unix.Openat(int(dir.Fd()), "systemctl", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return 0, e
	}
	f := os.NewFile(uintptr(fd), "doctor-os-systemctl")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&07000 != 0 || st.Mode&0111 == 0 || st.Nlink != 1 {
		return 0, errObservation
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", managerArgs()...)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = managerEnvironment()
	raw, e := runQuery(cmd)
	if e != nil {
		return 0, e
	}
	return parseManagerVersion(raw)
}

func kvmObservation() (state, state) {
	dir, e := trustedDirectory("/dev")
	if e != nil {
		return unobserved, unobserved
	}
	defer dir.Close()
	fd := int(dir.Fd())
	var before, after unix.Stat_t
	if e = unix.Fstatat(fd, "kvm", &before, unix.AT_SYMLINK_NOFOLLOW); errors.Is(e, unix.ENOENT) {
		return unavailable, unobserved
	} else if e != nil {
		return unobserved, unobserved
	}
	if !kvmDevice(before) {
		return unavailable, unobserved
	}
	// Permission observation only: do not open the device or create a VM. Device
	// cgroup/LSM policy may still deny a subsequent real KVM open/operation.
	e = unix.Faccessat(fd, "kvm", unix.R_OK|unix.W_OK, unix.AT_EACCESS|unix.AT_SYMLINK_NOFOLLOW)
	if unix.Fstatat(fd, "kvm", &after, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Rdev != after.Rdev || before.Mode != after.Mode {
		return unobserved, unobserved
	}
	if e == nil {
		return available, available
	}
	if errors.Is(e, unix.EACCES) || errors.Is(e, unix.EPERM) {
		return available, denied
	}
	return available, unobserved
}

func kvmDevice(s unix.Stat_t) bool {
	// Linux MISC_MAJOR/KVM_MINOR, not just any character device named kvm.
	// https://github.com/torvalds/linux/blob/master/include/linux/miscdevice.h
	return s.Mode&unix.S_IFMT == unix.S_IFCHR && unix.Major(s.Rdev) == 10 && unix.Minor(s.Rdev) == 232
}

func observe(ctx context.Context) observation {
	o := observation{os: runtime.GOOS, arch: runtime.GOARCH}
	if ctx.Err() != nil {
		return o
	}
	if dir, e := trustedDirectory("/proc/1"); e == nil {
		raw, e := readKernelFile(dir, "comm", unix.PROC_SUPER_MAGIC, 64)
		dir.Close()
		if e == nil {
			o.pid1 = unavailable
			if string(raw) == "systemd\n" {
				o.pid1 = available
			}
		}
	}
	if o.pid1 == available {
		if major, e := runningManagerVersion(ctx); e == nil {
			o.major, o.manager = major, available
		}
	}
	if dir, e := trustedDirectory("/sys/fs/cgroup"); e == nil {
		if e := filesystem(int(dir.Fd()), unix.CGROUP2_SUPER_MAGIC); e == nil {
			o.cgroup = available
			if raw, e := readKernelFile(dir, "cgroup.controllers", unix.CGROUP2_SUPER_MAGIC, 4096); e == nil {
				if missing, e := parseControllers(raw); e == nil {
					o.missing, o.controllers = missing, available
					if len(missing) != 0 {
						o.controllers = unavailable
					}
				}
			}
		} else if errors.Is(e, errFilesystem) {
			o.cgroup = unavailable
		}
		dir.Close()
	}
	o.kvm, o.access = kvmObservation()
	return o
}
