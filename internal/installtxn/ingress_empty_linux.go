//go:build linux

package installtxn

import (
	"errors"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const ingressCgroupParent = "/sys/fs/cgroup/system.slice"
const maxIngressEvents = 4096
const maxIngressGroups = 64
const maxIngressDepth = 16
const maxIngressEntries = 512

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
	if e = proveIngressSubtree(group, cgroup2FD); e != nil {
		return e
	}
	return sameIngressEntry(int(parent.Fd()), IngressUnit, pinned, true)
}

// Only disappearance AFTER a complete proof counts as absence. All traversal is
// read-only, descriptor anchored and bounded. Root populated is hierarchical,
// but root frozen does not establish that every descendant is unfrozen.
// checkFS is an unexported unit-test seam; production always passes cgroup2FD.
func proveIngressSubtree(group *os.File, checkFS func(int) error) error {
	var root unix.Stat_t
	if e := unix.Fstat(int(group.Fd()), &root); e != nil {
		return e
	}
	nodes := 0
	var walk func(*os.File, int) error
	walk = func(g *os.File, depth int) error {
		nodes++
		if nodes > maxIngressGroups || depth > maxIngressDepth {
			return ErrInventory
		}
		fd := int(g.Fd())
		if e := trustedStat(fd, true, 0); e != nil {
			return e
		}
		if e := checkFS(fd); e != nil {
			return e
		}
		var pinned unix.Stat_t
		if e := unix.Fstat(fd, &pinned); e != nil {
			return e
		}
		if pinned.Dev != root.Dev {
			return ErrInventory
		}
		if e := readIngressEvents(fd, checkFS); e != nil {
			return e
		}
		names, e := ingressNames(fd)
		if e != nil {
			return e
		}
		for _, name := range names {
			var before unix.Stat_t
			if e := unix.Fstatat(fd, name, &before, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return e
			}
			if before.Dev != root.Dev {
				return ErrInventory
			}
			switch before.Mode & unix.S_IFMT {
			case unix.S_IFREG: // Kernel control files, not arbitrary file content.
				continue
			case unix.S_IFDIR:
			default:
				return ErrInventory
			}
			childFD, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if e != nil {
				return e
			}
			child := os.NewFile(uintptr(childFD), "ingress-empty-descendant")
			var opened unix.Stat_t
			e = unix.Fstat(childFD, &opened)
			if e == nil && (opened.Dev != before.Dev || opened.Ino != before.Ino) {
				e = ErrInventory
			}
			if e == nil {
				e = walk(child, depth+1)
			}
			child.Close()
			if e != nil {
				return e
			}
			if e = sameIngressEntry(fd, name, before, true); e != nil {
				return e
			}
		}
		// Refuse inventory changes rather than overlooking a newly added child.
		after, e := ingressNames(fd)
		if e != nil {
			return e
		}
		if strings.Join(names, "\x00") != strings.Join(after, "\x00") {
			return ErrInventory
		}
		return readIngressEvents(fd, checkFS)
	}
	return walk(group, 0)
}

func ingressNames(fd int) ([]string, error) {
	listingFD, e := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	listing := os.NewFile(uintptr(listingFD), "ingress-empty-listing")
	defer listing.Close()
	names, e := listing.Readdirnames(maxIngressEntries + 1)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if len(names) > maxIngressEntries {
		return nil, ErrInventory
	}
	sort.Strings(names)
	return names, nil
}

func readIngressEvents(fd int, checkFS func(int) error) error {
	eventFD, e := unix.Openat(fd, "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	events := os.NewFile(uintptr(eventFD), "ingress-empty-events")
	defer events.Close()
	if e = trustedStat(eventFD, false, 0444); e != nil {
		return e
	}
	if e = checkFS(eventFD); e != nil {
		return e
	}
	var pinned, group unix.Stat_t
	if e = unix.Fstat(eventFD, &pinned); e != nil {
		return e
	}
	if e = unix.Fstat(fd, &group); e != nil {
		return e
	}
	if pinned.Dev != group.Dev {
		return ErrInventory
	}
	b, e := io.ReadAll(io.LimitReader(events, maxIngressEvents+1))
	if e != nil {
		return e
	}
	if e = parseIngressEmptyEvents(b); e != nil {
		return e
	}
	return sameIngressEntry(fd, "cgroup.events", pinned, false)
}

func sameIngressEntry(parent int, name string, pinned unix.Stat_t, absentOK bool) error {
	var current unix.Stat_t
	e := unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW)
	if absentOK && errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	if current.Mode&unix.S_IFMT != pinned.Mode&unix.S_IFMT || current.Dev != pinned.Dev || current.Ino != pinned.Ino {
		return ErrInventory
	}
	return nil
}
