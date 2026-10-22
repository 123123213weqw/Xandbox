//go:build linux

// Package warden is a minimal trusted lifetime-pipe supervisor, not a guest RPC
// endpoint. It and its child are born inside one already-limited host cgroup.
package warden

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Run consumes inherited fd 3 (lease reader) and fd 4 (cgroup.kill writer).
// Only sandboxd retains the lease writer. EOF kills the entire immutable group,
// including this root supervisor; jailer credential changes cannot clear it.
func Run(cgroup string, argv []string) error {
	if os.Geteuid() != 0 || len(argv) == 0 || !filepath.IsAbs(argv[0]) || cgroup == "" || filepath.Clean(cgroup) != cgroup || filepath.IsAbs(cgroup) || strings.HasPrefix(cgroup, "..") {
		return errors.New("invalid warden invocation")
	}
	// Duplicate before validating so a failed direct invocation never closes
	// unrelated runtime descriptors that happen to occupy fd 3 or fd 4.
	leaseFD, err := unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, 5)
	if err != nil {
		return errors.New("missing lease descriptor")
	}
	lease := os.NewFile(uintptr(leaseFD), "lease")
	defer lease.Close()
	killFD, err := unix.FcntlInt(4, unix.F_DUPFD_CLOEXEC, 5)
	if err != nil {
		return errors.New("missing kill descriptor")
	}
	kill := os.NewFile(uintptr(killFD), "kill")
	defer kill.Close()
	var pipeInfo unix.Stat_t
	if err := unix.Fstat(leaseFD, &pipeInfo); err != nil || pipeInfo.Mode&unix.S_IFMT != unix.S_IFIFO {
		return errors.New("warden requires inherited lifetime pipe")
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(killFD, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("warden requires cgroup-v2 kill descriptor")
	}
	group, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || strings.TrimSpace(string(group)) != "0::/"+cgroup {
		return errors.New("warden was not born in its assigned cgroup")
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", killFD))
	if err != nil || path != "/sys/fs/cgroup/"+cgroup+"/cgroup.kill" {
		return errors.New("warden kill descriptor does not match membership")
	}
	// Neither descriptor is passed through to jailer or VMM. In particular no
	// descendant can hold open a writer and suppress controller-death EOF.
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	stop := func() {
		for {
			_, _ = kill.Seek(0, 0)
			_, _ = kill.Write([]byte("1"))
			// Successful cgroup.kill kills this supervisor as well. If the
			// kernel rejected it, keep trying rather than leave a live child.
			time.Sleep(10 * time.Millisecond)
		}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() { <-signals; stop() }()
	go func() {
		var byte [1]byte
		_, _ = io.ReadFull(lease, byte[:]) // EOF, error OR unexpected data fences.
		stop()
	}()
	child := exec.Command(argv[0], argv[1:]...)
	child.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	_ = child.Run()
	stop()
	return nil
}
