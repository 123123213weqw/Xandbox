//go:build linux

package launch

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type fdGroup struct{ file *os.File }

func groupFromFD(fd int) (group, error) {
	if e := trustedStat(fd, true, false); e != nil {
		unix.Close(fd)
		return nil, e
	}
	var fs unix.Statfs_t
	if e := unix.Fstatfs(fd, &fs); e != nil {
		unix.Close(fd)
		return nil, e
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		unix.Close(fd)
		return nil, errors.New("cgroup2 anchor required")
	}
	return &fdGroup{os.NewFile(uintptr(fd), "launch-cgroup")}, nil
}
func openGroupPath(path string) (group, error) {
	f, e := trustedDirectory(path, false)
	if e != nil {
		return nil, e
	}
	fd, e := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	f.Close()
	if e != nil {
		return nil, e
	}
	return groupFromFD(fd)
}
func component(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00")
}
func (g *fdGroup) Open(name string) (group, error) {
	if !component(name) {
		return nil, errPolicy
	}
	fd, e := unix.Openat(int(g.file.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return groupFromFD(fd)
}
func (g *fdGroup) Mkdir(name string) (group, error) {
	if !component(name) {
		return nil, errPolicy
	}
	if e := unix.Mkdirat(int(g.file.Fd()), name, 0700); e != nil {
		return nil, e
	}
	return g.Open(name)
}
func (g *fdGroup) Read(name string) (string, error) {
	if !component(name) {
		return "", errPolicy
	}
	fd, e := unix.Openat(int(g.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", e
	}
	f := os.NewFile(uintptr(fd), "launch-interface")
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return "", e
	}
	if len(data) > 4096 {
		return "", errPolicy
	}
	return strings.TrimSpace(string(data)), nil
}
func (g *fdGroup) Write(name, value string) error {
	if !component(name) || len(value) > 4096 {
		return errPolicy
	}
	fd, e := unix.Openat(int(g.file.Fd()), name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "launch-interface")
	defer f.Close()
	n, e := f.WriteString(value)
	if e != nil {
		return e
	}
	if n != len(value) {
		return io.ErrShortWrite
	}
	return nil
}
func (g *fdGroup) Children() ([]string, error) {
	fd, e := unix.Openat(int(g.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "launch-inventory")
	defer f.Close()
	var result []string
	total := 0
	for {
		entries, e := f.ReadDir(64)
		if e != nil && e != io.EOF {
			return nil, e
		}
		total += len(entries)
		if total > 512 {
			return nil, errPolicy
		}
		for _, entry := range entries {
			if entry.IsDir() {
				result = append(result, entry.Name())
				if len(result) > 8 {
					return nil, errPolicy
				}
			}
		}
		if e == io.EOF {
			break
		}
	}
	return result, nil
}
func (g *fdGroup) Close() error { return g.file.Close() }
