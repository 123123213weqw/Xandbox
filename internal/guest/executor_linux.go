//go:build linux

package guest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

type guestGuard struct{}

type Executor struct {
	guard    *guestGuard
	root     string
	slots    chan struct{}
	poisoned atomic.Bool
}

// NewExecutor refuses to initialize on a normal host. These are accidental-host
// execution guards, not a defense against a malicious guest kernel or host root.
func NewExecutor() (*Executor, sandbox.Ref, string, error) {
	var ref sandbox.Ref
	stamp, err := os.ReadFile("/etc/xandbox-guest")
	if err != nil || string(stamp) != "Xandbox guest image v1\n" || os.Geteuid() != 0 {
		return nil, ref, "", errors.New("not an Xandbox guest image")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return nil, ref, "", err
	}
	guestFlag := false
	for _, field := range strings.Fields(string(cmdline)) {
		if field == "xandbox.guest=1" {
			guestFlag = true
		}
		if strings.HasPrefix(field, "xandbox.id=") {
			ref.ID = strings.TrimPrefix(field, "xandbox.id=")
		}
		if strings.HasPrefix(field, "xandbox.generation=") {
			ref.Generation = strings.TrimPrefix(field, "xandbox.generation=")
		}
	}
	if !guestFlag || !(guestwire.Request{Version: 1, Operation: "health", Ref: ref}).Valid() {
		return nil, ref, "", errors.New("missing guest boot identity")
	}
	cid, err := vsock.ContextID()
	if err != nil || cid <= 2 {
		return nil, ref, "", errors.New("guest vsock identity unavailable")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, ref, "", err
	}
	if err := bootstrap(); err != nil {
		return nil, ref, "", err
	}
	return &Executor{guard: &guestGuard{}, root: "/sys/fs/cgroup/xandbox", slots: make(chan struct{}, 2)}, ref, strings.TrimSpace(string(boot)), nil
}

func bootstrap() error {
	for _, path := range []string{"/workspace", "/sys/fs/cgroup"} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}
	if err := unix.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount cgroup2: %w", err)
	}
	if err := os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); err != nil {
		return err
	}
	if err := os.Mkdir("/sys/fs/cgroup/xandbox", 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if err := os.WriteFile("/sys/fs/cgroup/xandbox/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); err != nil {
		return err
	}
	if err := unix.Mount("/dev/vda", "/workspace", "ext4", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("mount workspace: %w", err)
	}
	if err := os.Chown("/workspace", 65534, 65534); err != nil {
		return err
	}
	if err := os.Chmod("/workspace", 0700); err != nil {
		return err
	}
	if err := os.Mkdir("/workspace/.tmp", 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if err := os.Chown("/workspace/.tmp", 65534, 65534); err != nil {
		return err
	}
	return nil
}

func (e *Executor) Ready() bool { return e.guard != nil && !e.poisoned.Load() }

// ActiveGroups observes kernel cgroup directories, not just an in-memory task
// count, so an operator can verify cancellation actually removed job groups.
func (e *Executor) ActiveGroups() (int, error) {
	if !e.Ready() {
		return 0, errors.New("guest executor fenced")
	}
	entries, err := os.ReadDir(e.root)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	return count, nil
}

func (e *Executor) Run(ctx context.Context, req guestwire.Request) (out sandbox.Output, retErr error) {
	if !e.Ready() || !req.Valid() || req.Operation != "exec" {
		return out, errors.New("guest executor unavailable")
	}
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	case <-ctx.Done():
		return out, ctx.Err()
	}
	if !e.Ready() {
		return out, errors.New("guest executor fenced")
	}
	group := filepath.Join(e.root, req.ExecutionID)
	if err := os.Mkdir(group, 0700); err != nil {
		return out, err
	}
	defer func() {
		if err := killAndRemove(group); err != nil {
			diagnostic("cleanup", err)
			e.poisoned.Store(true)
			retErr = errors.Join(retErr, errors.New("execution cgroup cleanup failed; guest fenced"))
		}
	}()
	for file, value := range map[string]string{"pids.max": "128", "memory.max": "134217728", "memory.swap.max": "0", "memory.oom.group": "1", "cpu.max": "100000 100000"} {
		if err := os.WriteFile(filepath.Join(group, file), []byte(value), 0); err != nil {
			diagnostic("policy", err)
			return out, err
		}
	}
	fd, err := os.Open(group)
	if err != nil {
		return out, err
	}
	defer fd.Close()
	// A small trusted child sets thread-local no_new_privs immediately before
	// exec. Setting prctl on one parent Go thread is NOT sufficient.
	cmd := exec.CommandContext(ctx, "/usr/bin/xandbox-agent", append([]string{"--run-child"}, req.Argv...)...)
	cmd.Dir = "/workspace"
	cmd.Env = []string{"PATH=/bin:/usr/bin", "HOME=/workspace", "TMPDIR=/workspace/.tmp", "LANG=C.UTF-8"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}, Setsid: true, UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	cmd.Cancel = func() error { return os.WriteFile(filepath.Join(group, "cgroup.kill"), []byte("1"), 0) }
	cmd.WaitDelay = time.Second
	capture := &capture{limit: req.MaxOutputBytes}
	cmd.Stdout = streamWriter{capture: capture}
	cmd.Stderr = streamWriter{capture: capture, stderr: true}
	err = cmd.Run()
	out = capture.output()
	if ctx.Err() != nil {
		out.ExitCode = -1
		return out, ctx.Err()
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		out.ExitCode = exit.ExitCode()
		return out, nil
	}
	if err != nil {
		diagnostic("launch", err)
		out.ExitCode = -1
		return out, errors.New("guest command could not be executed")
	}
	return out, nil
}

// Fixed stage + errno only: do not log argv, output, filenames, or raw errors.
func diagnostic(stage string, err error) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		fmt.Fprintf(os.Stderr, "guest executor failure stage=%s errno=%d\n", stage, errno)
	} else {
		fmt.Fprintf(os.Stderr, "guest executor failure stage=%s\n", stage)
	}
}

// RunChild is the unprivileged, cgroup-contained helper entry point. It refuses
// ordinary hosts even if invoked manually. It never interprets shell syntax;
// an explicit shell argv executes only after all guest guards succeed.
func RunChild(args []string) error {
	if os.Geteuid() != 65534 || os.Getegid() != 65534 || len(args) == 0 {
		return errors.New("guest child identity unavailable")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return err
	}
	valid := false
	for _, field := range strings.Fields(string(cmdline)) {
		if field == "xandbox.guest=1" {
			valid = true
		}
	}
	groups, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	contained := false
	for _, line := range strings.Split(string(groups), "\n") {
		if strings.HasPrefix(line, "0::/xandbox/") && len(strings.TrimPrefix(line, "0::/xandbox/")) == 32 {
			contained = true
		}
	}
	if !valid || !contained {
		return errors.New("guest child execution guard rejected")
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return errors.New("guest command not found")
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 256, Max: 256}); err != nil {
		return err
	}
	return unix.Exec(path, args, os.Environ())
}

func killAndRemove(group string) error {
	if err := os.WriteFile(filepath.Join(group, "cgroup.kill"), []byte("1"), 0); err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		events, err := os.ReadFile(filepath.Join(group, "cgroup.events"))
		if err != nil {
			return err
		}
		if strings.Contains("\n"+string(events), "\npopulated 0\n") {
			return os.Remove(group)
		}
		if time.Now().After(deadline) {
			return errors.New("execution cgroup failed to drain")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type capture struct {
	mu             sync.Mutex
	limit          int
	stdout, stderr bytes.Buffer
	truncated      bool
}
type streamWriter struct {
	capture *capture
	stderr  bool
}

func (w streamWriter) Write(p []byte) (int, error) {
	c := w.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	remaining := c.limit - c.stdout.Len() - c.stderr.Len()
	if len(p) > remaining {
		p = p[:remaining]
		c.truncated = true
	}
	if w.stderr {
		c.stderr.Write(p)
	} else {
		c.stdout.Write(p)
	}
	return n, nil // Drain excess bytes instead of blocking the child pipe.
}
func (c *capture) output() sandbox.Output {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sandbox.Output{Stdout: c.stdout.String(), Stderr: c.stderr.String(), Truncated: c.truncated}
}
