//go:build linux

package installtxn

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const ingressCgroupParent = "/sys/fs/cgroup/system.slice"
const maxIngressEvents = 4096

// populated covers the whole subtree, not merely cgroup.procs or MainPID.
// https://docs.kernel.org/admin-guide/cgroup-v2.html#un-populated-notification
// This is an empty/live-process proof, NOT deletion or full resource reclaim.
func parseIngressEmptyEvents(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxIngressEvents || raw[len(raw)-1] != '\n' || strings.ContainsAny(string(raw), "\r\x00") {
		return ErrInventory
	}
	fields := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 || (parts[0] != "populated" && parts[0] != "frozen") || fields[parts[0]] || parts[1] != "0" {
			return ErrInventory
		}
		fields[parts[0]] = true
	}
	if len(fields) != 2 {
		return ErrInventory
	}
	return nil
}
func cgroup2FD(fd int) error {
	var fs unix.Statfs_t
	if e := unix.Fstatfs(fd, &fs); e != nil {
		return e
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return ErrPlatform
	}
	return nil
}

// Fixed, read-only host proof. A missing unit directory counts as absent ONLY
// below an already validated real cgroup-v2 parent. Missing events in an opened
// group, fake filesystem reports, survivors and a frozen group fail closed.
// No freeze, kill, migration, directory removal or other write is performed.
func (f *filesystem) ingressEmpty() error {
	parent, e := f.directory(ingressCgroupParent)
	if e != nil {
		return e
	}
	defer parent.Close()
	if e = cgroup2FD(int(parent.Fd())); e != nil {
		return e
	}
	fd, e := unix.Openat(int(parent.Fd()), IngressUnit, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	group := os.NewFile(uintptr(fd), "ingress-empty-cgroup")
	defer group.Close()
	if e = trustedStat(fd, true, 0); e != nil {
		return e
	}
	if e = cgroup2FD(fd); e != nil {
		return e
	}
	var pinned unix.Stat_t
	if e = unix.Fstat(fd, &pinned); e != nil {
		return e
	}
	eventFD, e := unix.Openat(fd, "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	events := os.NewFile(uintptr(eventFD), "ingress-empty-events")
	defer events.Close()
	if e = trustedStat(eventFD, false, 0444); e != nil {
		return e
	}
	if e = cgroup2FD(eventFD); e != nil {
		return e
	}
	b, e := io.ReadAll(io.LimitReader(events, maxIngressEvents+1))
	if e != nil {
		return e
	}
	if e = parseIngressEmptyEvents(b); e != nil {
		return e
	}
	var current unix.Stat_t
	e = unix.Fstatat(int(parent.Fd()), IngressUnit, &current, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return nil
	} // the proved empty group disappeared
	if e != nil {
		return e
	}
	if current.Mode&unix.S_IFMT != unix.S_IFDIR || current.Dev != pinned.Dev || current.Ino != pinned.Ino {
		return ErrInventory
	}
	return nil
}
