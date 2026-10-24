//go:build linux

package installtxn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func operationFixture(t *testing.T) *filesystem {
	t.Helper()
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(base+Root, 0700); e != nil {
		t.Fatal(e)
	}
	root, e := os.Open(base)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	f := &filesystem{root: root}
	unlock, e := f.initialLock(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	unlock()
	return f
}
func operationDenied(t *testing.T, f *filesystem, exclusive bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	unlock, e := f.operationLock(ctx, exclusive)
	if e == nil {
		unlock()
		t.Fatal("conflicting operation lock acquired")
	}
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("not a bounded lock conflict", e)
	}
}
func operationAllowed(t *testing.T, f *filesystem, exclusive bool) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, e := f.operationLock(ctx, exclusive)
	if e != nil {
		t.Fatal("compatible operation lock refused", e)
	}
	return unlock
}
func TestOperationLockSharedExclusiveIndependentFlockAndDescriptorLifetime(t *testing.T) {
	f := operationFixture(t)
	shared1 := operationAllowed(t, f, false)
	shared2 := operationAllowed(t, f, false)
	operationDenied(t, f, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// The EX file proof can coexist with ordinary operation SH. Keeping the
	// latter across manager/ACK work must not block the cap0 SH startup gate.
	files, e := f.existingLock(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	files()
	gate, e := f.existingLock(ctx, false)
	if e != nil {
		t.Fatal(e)
	}
	gate()
	shared1()
	operationDenied(t, f, true)
	unrelated, e := f.open(Root+"/.lock", unix.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	unrelated.Close()
	operationDenied(t, f, true) // a POSIX process lock would be released here
	shared2()
	exclusive := operationAllowed(t, f, true)
	operationDenied(t, f, false)
	operationDenied(t, f, true)
	gate, e = f.existingLock(ctx, false)
	if e != nil {
		t.Fatal("maintenance blocks read-only gate", e)
	}
	gate()
	exclusive()
	operationAllowed(t, f, true)()
}

func TestOperationLockCancellationIdentityAndInvalidInventoryNeverRepair(t *testing.T) {
	for _, kind := range []string{"missing", "nonempty", "hardlink", "symlink", "fifo", "mode", "pre-cancelled", "replaced-before-acquire", "replaced-after-acquire", "changed-after-acquire"} {
		t.Run(kind, func(t *testing.T) {
			f := operationFixture(t)
			path := f.root.Name() + Root + "/.lock"
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch kind {
			case "missing":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
			case "nonempty":
				if e := os.WriteFile(path, []byte("foreign"), 0600); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(path, path+"-foreign"); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("foreign", path); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
				if e := unix.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := os.Chmod(path, 0640); e != nil {
					t.Fatal(e)
				}
			case "pre-cancelled":
				cancel()
			case "replaced-before-acquire", "replaced-after-acquire", "changed-after-acquire":
				at := "operation-lock-acquired"
				if kind == "replaced-before-acquire" {
					at = "operation-lock-opened"
				}
				f.hook = func(stage string) error {
					if stage != at {
						return nil
					}
					if kind == "changed-after-acquire" {
						return os.WriteFile(path, []byte("foreign"), 0600)
					}
					if e := os.Rename(path, path+"-original"); e != nil {
						return e
					}
					return os.WriteFile(path, nil, 0600)
				}
			}
			before, e := os.Lstat(path)
			unlock, e := f.operationLock(ctx, true)
			if e == nil {
				unlock()
				t.Fatal("invalid operation proof accepted")
			}
			if kind == "missing" {
				if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("lost lock recreated")
				}
			}
			if kind == "nonempty" || kind == "changed-after-acquire" {
				b, e := os.ReadFile(path)
				if e != nil || string(b) != "foreign" {
					t.Fatal("unknown bytes truncated/repaired")
				}
			}
			if kind == "pre-cancelled" {
				after, e := os.Lstat(path)
				if e != nil || !os.SameFile(before, after) || !errors.Is(ctx.Err(), context.Canceled) {
					t.Fatal("cancelled acquisition changed original inode")
				}
			}
		})
	}
}

func TestInitialOperationLockFreshOnlyAndOriginalInodePreserved(t *testing.T) {
	f := operationFixture(t)
	path := f.root.Name() + Root + "/.lock"
	before, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	unlock, e := f.initialOperationLock(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	files, e := f.existingLock(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	files()
	unlock()
	after, e := os.Stat(path)
	if e != nil || !os.SameFile(before, after) || after.Size() != 0 {
		t.Fatal("bootstrap replaced/modified original lock")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Dir(path)+"/commit.json", []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	if unlock, e = f.initialOperationLock(context.Background()); e == nil {
		unlock()
		t.Fatal("used directory lost lock bootstrapped")
	}
	if _, e = os.Stat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("used lock recreated")
	}
	if e = os.Remove(filepath.Dir(path) + "/commit.json"); e != nil {
		t.Fatal(e)
	}
	unlock, e = f.initialOperationLock(context.Background())
	if e != nil {
		t.Fatal("fresh empty directory refused", e)
	}
	unlock()
}

// Test-only process entry. Production binaries have no alternate root, lock
// inspection command, fixture environment switch or synthetic maintenance ACK.
func TestOperationLockProcessHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_OPERATION_ROOT")
	if root == "" {
		return
	}
	if os.Getenv("XANDBOX_TEST_OPERATION_MODE") == "no-inherit" {
		paths, e := filepath.Glob("/proc/self/fd/*")
		if e != nil {
			os.Exit(71)
		}
		for _, p := range paths {
			s, e := os.Readlink(p)
			if e == nil && strings.HasPrefix(s, root+Root+"/.lock") {
				os.Exit(72)
			}
		}
		os.Exit(0)
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(73)
	}
	f := &filesystem{root: dir}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	unlock, e := f.operationLock(ctx, os.Getenv("XANDBOX_TEST_OPERATION_MODE") == "exclusive")
	if e != nil {
		os.Exit(74)
	}
	defer unlock()
	fmt.Fprintln(os.Stdout, "LOCKED")
	if _, e = io.Copy(io.Discard, os.Stdin); e != nil {
		os.Exit(75)
	}
	// os.Exit deliberately bypasses close/unlock defers: kernel lifetime, not
	// a hand-written unlock, must release the child's OFD lock.
	os.Exit(0)
}

type operationChild struct {
	command *exec.Cmd
	input   io.WriteCloser
}

func startOperationChild(t *testing.T, ctx context.Context, root, mode string) operationChild {
	t.Helper()
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOperationLockProcessHelper$")
	c.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_OPERATION_ROOT=" + root, "XANDBOX_TEST_OPERATION_MODE=" + mode}
	input, e := c.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := c.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		input.Close()
		if c.ProcessState == nil {
			c.Process.Kill()
			c.Wait()
		}
	})
	lines := bufio.NewScanner(output)
	if !lines.Scan() || lines.Text() != "LOCKED" {
		t.Fatal("child did not acquire actual lock")
	}
	return operationChild{c, input}
}

func TestOperationFourProcessesSharedDeathAndExclusiveAdmission(t *testing.T) {
	f := operationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	children := make([]operationChild, 4)
	for i := range children {
		children[i] = startOperationChild(t, ctx, f.root.Name(), "shared")
	}
	operationDenied(t, f, true)
	if e := children[0].command.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e := children[0].command.Wait(); e == nil {
		t.Fatal("killed child reported success")
	}
	children[0].input.Close()
	operationDenied(t, f, true) // killing one reader does not release other OFDs
	for _, child := range children[1:] {
		child.input.Close()
		if e := child.command.Wait(); e != nil {
			t.Fatal(e)
		}
	}
	operationAllowed(t, f, true)()
	x := startOperationChild(t, ctx, f.root.Name(), "exclusive")
	operationDenied(t, f, false)
	if e := x.command.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e := x.command.Wait(); e == nil {
		t.Fatal("killed exclusive child reported success")
	}
	x.input.Close()
	operationAllowed(t, f, false)()
	entries, e := f.names(Root)
	if e != nil || len(entries) != 1 || entries[0] != ".lock" {
		t.Fatal("operation created new journal/lock entries")
	}
}

func TestOperationDescriptorCloseOnExecAndSameInodeReadOnlyGate(t *testing.T) {
	f := operationFixture(t)
	in, e := f.acquireOperationLock(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	flags, e := unix.FcntlInt(in.Fd(), unix.F_GETFD, 0)
	if e != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("lock capability inheritable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOperationLockProcessHelper$")
	c.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_OPERATION_ROOT=" + f.root.Name(), "XANDBOX_TEST_OPERATION_MODE=no-inherit"}
	if b, e := c.CombinedOutput(); e != nil || len(b) != 0 {
		t.Fatal("operation descriptor escaped exec", e)
	}
	gate, e := f.existingLock(ctx, false)
	if e != nil {
		t.Fatal("ordinary read-only flock gate blocked", e)
	}
	gate()
	operationDenied(t, f, false)
}

type operationModelManager struct {
	*modelManager
	t            *testing.T
	f            *filesystem
	managerCalls int
}

func (m *operationModelManager) reconcile(ctx context.Context) error {
	m.managerCalls++
	operationDenied(m.t, m.f, true)
	// A manager-started cap0 verifier still needs ONLY its ordinary flock SH.
	gate, e := m.f.existingLock(ctx, false)
	if e != nil {
		return e
	}
	gate()
	return m.modelManager.reconcile(ctx)
}

func TestOperationActualInstallAndReconcileScopesCoverManagerWithReadOnlyGate(t *testing.T) {
	f, p, baseManager := fixture(t)
	pinModelSelf(t, p)
	m := &operationModelManager{modelManager: baseManager, t: t, f: f}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	load := func(context.Context, Plan, bool) (*prepared, func(), error) { return p, func() {}, nil }
	got, e := installOperation(ctx, f, p.plan, request(), m, load)
	if e != nil || !got.FilesCommitted || !got.ManagerReconciled || m.managerCalls != 1 {
		t.Fatal("ordinary install scope", e)
	}
	operationAllowed(t, f, true)() // operation released only after the receipt
	got, e = reconcileOperation(ctx, f, request(), m)
	if e != nil || !got.ManagerReconciled || m.managerCalls != 2 {
		t.Fatal("ordinary reconcile scope", e)
	}
	operationAllowed(t, f, true)()
}

func TestOperationActualReconfigurationScopeCoversACKAndErrorRelease(t *testing.T) {
	f, tx, p := rotationFixture(t, true)
	m := &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}, active: true}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	samples, activations := 0, 0
	m.onPolicy = func(_ uint64, activate bool) {
		samples++
		operationDenied(t, f, true)
		if activate {
			activations++
			gate, e := f.existingLock(ctx, false)
			if e != nil {
				t.Fatal("manager verifier deadlocked", e)
			}
			gate()
		}
	}
	req := strings.Repeat("b", 32)
	got, e := reconfigureOperation(ctx, f, p, 1, req, m)
	if e != nil || got.Revision != 2 || !got.ManagerReconciled || samples < 2 || activations != 1 {
		t.Fatal("ordinary reconfigure scope", e)
	}
	operationAllowed(t, f, true)()
	before := samples
	got, e = reconcileOperation(ctx, f, req, m)
	if e != nil || !got.ManagerReconciled || samples <= before {
		t.Fatal("rotation reconcile scope", e)
	}
	operationAllowed(t, f, true)()
	if _, e = reconfigureOperation(ctx, f, p, 1, tx.RequestID, m); !errors.Is(e, ErrConflict) {
		t.Fatal("initial request reuse accepted", e)
	}
	operationAllowed(t, f, true)() // every error path must close its operation FD
}

func TestOperationActualMutationEntriesWaitWithoutFileOrManagerWork(t *testing.T) {
	f, tx, p := rotationFixture(t, true)
	m := &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}, active: true}}
	for _, kind := range []string{"reconfigure", "reconcile", "apply"} {
		t.Run(kind, func(t *testing.T) {
			exclusive := operationAllowed(t, f, true)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			writes := 0
			f.hook = func(at string) error {
				if at != "operation-lock-opened" {
					writes++
				}
				return nil
			}
			var e error
			switch kind {
			case "reconfigure":
				_, e = reconfigureOperation(ctx, f, p, 1, strings.Repeat("b", 32), m)
			case "reconcile":
				_, e = reconcileOperation(ctx, f, tx.RequestID, m)
			case "apply":
				_, e = installOperation(ctx, f, tx.Plan, tx.RequestID, m, func(context.Context, Plan, bool) (*prepared, func(), error) {
					t.Fatal("load under maintenance")
					return nil, nil, ErrPolicy
				})
			}
			f.hook = nil
			exclusive()
			if !errors.Is(e, context.DeadlineExceeded) || writes != 0 || m.reconcileCalls != 0 || m.activationCalls != 0 {
				t.Fatal("mutation ran beneath exclusive operation", e)
			}
			if e = f.verifyTransaction(context.Background(), tx); e != nil {
				t.Fatal("blocked mutation changed file proof", e)
			}
			operationAllowed(t, f, true)()
		})
	}
}
