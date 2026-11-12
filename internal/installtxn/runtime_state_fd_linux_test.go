//go:build linux

package installtxn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"golang.org/x/sys/unix"
)

// Owned TEST ELF only: one private regular file, no node service/VMM/guest.
func TestRuntimeStateFDProbeHelper(t *testing.T) {
	path := os.Getenv("XANDBOX_TEST_FD_LOCK")
	if path == "" {
		return
	}
	f, e := os.OpenFile(path, os.O_RDWR|unix.O_NOFOLLOW, 0)
	if e != nil {
		os.Exit(61)
	}
	defer f.Close()
	mode := os.Getenv("XANDBOX_TEST_FD_MODE")
	switch mode {
	case "exclusive", "duplicate":
		e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	case "waiter":
		fmt.Println("ready")
		e = unix.Flock(int(f.Fd()), unix.LOCK_EX)
	case "shared":
		e = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	case "posix", "ofd":
		cmd := unix.F_SETLK
		if mode == "ofd" {
			cmd = unix.F_OFD_SETLK
		}
		e = unix.FcntlFlock(f.Fd(), cmd, &unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0})
	case "open":
	default:
		os.Exit(62)
	}
	if e != nil {
		os.Exit(63)
	}
	if mode == "duplicate" {
		fd, err := unix.Dup(int(f.Fd()))
		if err != nil {
			os.Exit(64)
		}
		defer unix.Close(fd)
	}
	fmt.Println("ready")
	var command string
	if _, e = fmt.Fscanln(os.Stdin, &command); e == nil && command == "unlock" {
		if unix.Flock(int(f.Fd()), unix.LOCK_UN) != nil {
			os.Exit(65)
		}
		fmt.Println("unlocked")
		_, _ = fmt.Fscanln(os.Stdin, &command)
	}
}

func stateFDProbeChild(t *testing.T, path, mode string) (*exec.Cmd, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeStateFDProbeHelper$")
	cmd.Env = []string{"GOMAXPROCS=2", "GOMEMLIMIT=" + os.Getenv("GOMEMLIMIT"), "XANDBOX_TEST_FD_LOCK=" + path, "XANDBOX_TEST_FD_MODE=" + mode}
	input, e := cmd.StdinPipe()
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		input.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		cancel()
	})
	scan := bufio.NewScanner(output)
	if !scan.Scan() || scan.Text() != "ready" {
		t.Fatal("owned helper did not initialize", scan.Err())
	}
	return cmd, func() {
		t.Helper()
		if _, e := fmt.Fprintln(input, "unlock"); e != nil || !scan.Scan() || scan.Text() != "unlocked" {
			t.Fatal("owned helper unlock synchronization", e, scan.Err())
		}
	}
}

func TestRuntimeStateFDKernelRowRetainsOriginalExactLockPredicate(t *testing.T) {
	id := runtimeStateIdentity{LockDevice: unix.Mkdev(8, 1), LockInode: 99}
	good := "1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n"
	cases := [][]byte{[]byte(good), []byte(good + good), []byte("2: FLOCK ADVISORY WRITE 456 08:02:100 0 EOF\n")}
	words := strings.Fields(good)
	for i := range words {
		for _, value := range []string{"", "0", "124", "READ", "POSIX", "OFDLCK", "->", "08:01:100", "08:02:99", "08:xx:99", "1", "Eof", "private"} {
			row := append([]string(nil), words...)
			row[i] = value
			cases = append(cases, []byte(strings.Join(row, " ")+"\n"))
		}
	}
	for i, row := range cases {
		raw := stateFDInfoFixture("lock:\t" + strings.ReplaceAll(strings.TrimSuffix(string(row), "\n"), "\n", "\nlock:\t") + "\n")
		one, e := stateFDInfoLockRecord(raw, id.LockInode)
		if e == nil {
			e = stateKernelLockOwner(one, id, 123)
		}
		old := originalStateKernelLockOwnerCe053(row, id, 123)
		if e == nil && old != nil {
			t.Fatal("FD proof weakened original row predicate", i)
		}
		if i == 0 && e != nil {
			t.Fatal("valid bound FD record refused", e)
		}
	}
}

func TestRuntimeStateFDRealOwnerRequiresOriginalInodePathAndIncarnation(t *testing.T) {
	for _, kind := range []string{"exclusive", "open", "shared", "posix", "ofd", "duplicate", "foreign-holder", "wrong-incarnation", "dead", "unlock", "path-rebind", "root-rebind", "mode", "hardlink", "nonempty", "ctime", "canceled", "after-path-rebind", "after-root-rebind", "after-death", "after-mode", "observation-cut"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.MkdirAll(root+stateDir, 0700); e != nil {
				t.Fatal(e)
			}
			path := root + stateDir + "/controller.lock"
			if e := os.WriteFile(path, nil, 0600); e != nil {
				t.Fatal(e)
			}
			dir, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			f := &filesystem{root: dir}
			lease, e := f.openRuntimeState()
			if e != nil {
				t.Fatal(e)
			}
			id := lease.id
			defer lease.close()
			mode := kind
			switch kind {
			case "foreign-holder":
				if e = acquireRuntimeState(lease); e != nil {
					t.Fatal(e)
				}
				mode = "open"
			case "wrong-incarnation", "dead", "unlock", "path-rebind", "root-rebind", "mode", "hardlink", "nonempty", "ctime", "canceled", "after-path-rebind", "after-root-rebind", "after-death", "after-mode", "observation-cut":
				mode = "exclusive"
			}
			child, unlock := stateFDProbeChild(t, path, mode)
			watch, e := nodecontrol.NewProcessWatch(child.Process.Pid)
			if e != nil {
				t.Fatal(e)
			}
			defer watch.Close()
			process := watch.Identity()
			switch kind {
			case "wrong-incarnation":
				process.StartTicks++
			case "dead":
				if e = child.Process.Kill(); e != nil {
					t.Fatal(e)
				}
				_ = child.Wait()
			case "unlock":
				unlock()
			case "path-rebind":
				if e = os.Rename(path, path+".old"); e == nil {
					e = os.WriteFile(path, nil, 0600)
				}
			case "root-rebind":
				if e = os.Rename(root+stateDir, root+stateDir+".old"); e == nil {
					e = os.Mkdir(root+stateDir, 0700)
				}
			case "mode":
				e = os.Chmod(path, 0644)
			case "hardlink":
				e = os.Link(path, path+".alias")
			case "nonempty":
				e = os.WriteFile(path, []byte("unknown"), 0600)
			case "ctime":
				id.LockChangeNanos = (id.LockChangeNanos + 1) % 1_000_000_000
			}
			if e != nil {
				t.Fatal(e)
			}
			before := coreTree(t, root)
			hit := false
			if strings.HasPrefix(kind, "after-") || kind == "observation-cut" {
				f.hook = func(at string) error {
					if at != "runtime-state-fd-after-observation" {
						return nil
					}
					hit = true
					var err error
					switch kind {
					case "after-path-rebind":
						if err = os.Rename(path, path+".old"); err == nil {
							err = os.WriteFile(path, nil, 0600)
						}
					case "after-root-rebind":
						if err = os.Rename(root+stateDir, root+stateDir+".old"); err == nil {
							err = os.Mkdir(root+stateDir, 0700)
						}
					case "after-death":
						err = child.Process.Kill()
						_ = child.Wait()
					case "after-mode":
						err = os.Chmod(path, 0644)
					case "observation-cut":
						return interrupted
					}
					if err != nil {
						t.Fatal(err)
					}
					before = coreTree(t, root)
					return nil
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "canceled" {
				cancel()
			}
			e = f.runtimeStateOwnedBy(ctx, id, process)
			if f.hook != nil && !hit {
				t.Fatal("original-observation cut not reached", e)
			}
			if kind == "canceled" && !errors.Is(e, context.Canceled) || kind == "observation-cut" && !errors.Is(e, interrupted) {
				t.Fatal("primary cut/cancel cause lost", e)
			}
			if (e == nil) != (kind == "exclusive") || !reflect.DeepEqual(before, coreTree(t, root)) {
				t.Fatal("uncertain owner accepted or private files changed", e)
			}
			if kind == "duplicate" && (e == nil || e.Error() != "runtime proof:/state-fd-multiple") {
				t.Fatal("descriptor aliases were deduplicated", e)
			}
		})
	}
	if d, e := stateProcDirectory(unix.AT_FDCWD, t.TempDir()); e == nil {
		d.Close()
		t.Fatal("non-procfs source accepted")
	}
}

func TestRuntimeStateFDMetadataChecksEveryOriginalField(t *testing.T) {
	id := runtimeStateIdentity{LockDevice: unix.Mkdev(8, 1), LockInode: 99, LockChangeSeconds: 1234, LockChangeNanos: 56}
	st := unix.Stat_t{Dev: id.LockDevice, Ino: id.LockInode, Mode: unix.S_IFREG | 0600, Nlink: 1, Uid: uint32(os.Geteuid()), Ctim: unix.Timespec{Sec: id.LockChangeSeconds, Nsec: id.LockChangeNanos}}
	if !stateFDMatches(st, id) {
		t.Fatal("valid metadata")
	}
	for _, kind := range []string{"device", "inode", "mode", "type", "link", "uid", "size", "seconds", "nanos"} {
		t.Run(kind, func(t *testing.T) {
			q := st
			switch kind {
			case "device":
				q.Dev++
			case "inode":
				q.Ino++
			case "mode":
				q.Mode |= 0004
			case "type":
				q.Mode = unix.S_IFDIR | 0600
			case "link":
				q.Nlink++
			case "uid":
				q.Uid++
			case "size":
				q.Size++
			case "seconds":
				q.Ctim.Sec++
			case "nanos":
				q.Ctim.Nsec++
			}
			if stateFDMatches(q, id) {
				t.Fatal("original metadata guard lost")
			}
		})
	}
}

func TestRuntimeStateFDUncertainOriginalNeverPersistsStopOrSignals(t *testing.T) {
	for _, kind := range []string{"state-fd-unlocked", "state-fd-shared", "state-fd-duplicate"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			x.client.Close()
			old := x.children[MainUnit]
			if e := old.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			_ = old.Wait()
			x.children[MainUnit] = runtimeStopChildMode(t, x.f.root.Name(), "main", kind)
			var e error
			x.client, e = nodecontrol.NewPinnedClient(filepath.Join(x.f.root.Name(), stateDir), x.children[MainUnit].Process.Pid)
			if e != nil {
				t.Fatal(e)
			}
			defer x.client.Close()
			s := x.scope(t)
			x.drain(t, s)
			before := coreTree(t, x.f.root.Name())
			r, e := x.stop(context.Background(), s, x.client)
			if e == nil || r.ExecutionStopped || len(x.jobs) != 0 || s.state != nil || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
				t.Fatal("uncertain FD owner authorized Stop or changed files", r, e, x.jobs)
			}
			if yes, e := x.f.exists(runtimeStopRoot); e != nil || yes {
				t.Fatal("uncertain FD owner acquired Stop namespace", e)
			}
		})
	}
}

func TestRuntimeStateFDGlobalVetoRetainsEveryOriginalNegativeRow(t *testing.T) {
	id := runtimeStateIdentity{LockDevice: unix.Mkdev(8, 1), LockInode: 99}
	good := "1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n"
	raws := [][]byte{nil, []byte("\n"), []byte(good), []byte(good + good), []byte("8: FLOCK ADVISORY WRITE 456 08:02:100 0 EOF\n"), []byte("2: -> FLOCK ADVISORY WRITE 456 08:01:99 0 EOF\n" + good)}
	seed := uint32(0x71f42a)
	for n := 0; n < 4096; n++ {
		b := []byte(good)
		for k := 0; k < 1+n%5; k++ {
			seed = 1664525*seed + 1013904223
			b[int(seed)%len(b)] = byte(seed >> 24)
		}
		raws = append(raws, b)
	}
	for _, n := range []int{4<<20 - 1, 4 << 20, 4<<20 + 1} {
		b := make([]byte, n)
		copy(b, good)
		b[n-1] = '\n'
		raws = append(raws, b)
	}
	for i, raw := range raws {
		old := stateKernelLockOwner(raw, id, 123)
		var typed *runtimeProofError
		cardinalityOnly := errors.As(old, &typed) && (typed.stage == proofStateLockOwnerMissing || typed.stage == proofStateLockOwnerAmbiguous)
		e := stateKernelLockVeto(raw, id, 123)
		if (e == nil) != (old == nil || cardinalityOnly) {
			t.Fatal("original negative row lost", i, e, old)
		}
		if e != nil && (e.Error() != old.Error() || errors.Is(e, ErrInventory) != errors.Is(old, ErrInventory) || errors.Is(e, ErrConflict) != errors.Is(old, ErrConflict)) {
			t.Fatal("negative class/stage changed", i)
		}
	}
}

func TestRuntimeStateFDActualBlockedWaiterStillVetoesBeforeStop(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.drain(t, s)
	lease, e := x.f.openRuntimeState()
	if e != nil {
		t.Fatal(e)
	}
	defer lease.close()
	waiter, _ := stateFDProbeChild(t, x.f.root.Name()+stateDir+"/controller.lock", "waiter")
	// Fixture readiness only: wait boundedly for OUR owned child to appear as
	// an actual kernel waiter, not a proof retry or a whole-gate rerun.
	deadline := time.Now().Add(2 * time.Second)
	seen := false
	for time.Now().Before(deadline) {
		raw, err := boundedProcessFile("/proc/locks", 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			v := strings.Fields(line)
			if len(v) == 9 && v[1] == "->" && v[5] == fmt.Sprint(waiter.Process.Pid) {
				// The original per-row parser must bind this exact target too.
				if e = stateKernelLockOwner([]byte(line+"\n"), lease.id, x.client.Identity().PID); errors.Is(e, ErrConflict) && strings.Contains(e.Error(), "state-lock-owner-mismatch") {
					seen = true
				}
			}
		}
		if seen {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !seen {
		t.Fatal("owned original-inode blocked waiter not observed")
	}
	before := coreTree(t, x.f.root.Name())
	result, e := x.stop(context.Background(), s, x.client)
	if e == nil || !errors.Is(e, ErrConflict) || !strings.Contains(e.Error(), "state-lock-owner-mismatch") || result.ExecutionStopped || len(x.jobs) != 0 || !reflect.DeepEqual(before, coreTree(t, x.f.root.Name())) {
		t.Fatal("FD witness overrode original waiter veto", result, e, x.jobs)
	}
	if yes, e := x.f.exists(runtimeStopRoot); e != nil || yes {
		t.Fatal("waiter acquired Stop namespace", e)
	}
}
