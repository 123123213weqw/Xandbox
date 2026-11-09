//go:build linux

package installtxn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ownStateModel(ctx context.Context, x *stopTestModel, s *runtimeScope) error {
	return s.ownStoppedStateWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), x.manager, x.proof.empty)
}

func TestRuntimeStateOriginalDaemonLockRetainedAcrossScope(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.drain(t, s)
	if e := ownStateModel(context.Background(), x, s); e == nil {
		t.Fatal("drain certified state ownership")
	}
	p, e := x.f.openRuntimeState()
	if e != nil {
		t.Fatal(e)
	}
	if e = acquireRuntimeState(p); !errors.Is(e, unix.EWOULDBLOCK) {
		t.Fatal("model daemon did not hold real BSD lock", e)
	}
	p.close()
	if _, e = x.stop(context.Background(), s, x.client); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 2; n++ {
		if e = ownStateModel(context.Background(), x, s); e != nil {
			t.Fatal(e)
		}
	}
	p, e = x.f.openRuntimeState()
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	if e = acquireRuntimeState(p); !errors.Is(e, unix.EWOULDBLOCK) {
		t.Fatal("scope lost separate state lock", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	file, e := x.f.existingLock(ctx, true)
	if e != nil {
		t.Fatal("unnecessary file flock", e)
	}
	file()
	if e = s.ownStoppedState(ctx, digest(encode(x.tx)), runtimeReq("b"), x.manager); e == nil {
		t.Fatal("fake cgroup authorized production state ownership")
	}
	s.close()
	if e = acquireRuntimeState(p); e != nil {
		t.Fatal("close leaked original state lease", e)
	}
	if e = ownStateModel(context.Background(), x, s); !errors.Is(e, ErrConflict) {
		t.Fatal("closed scope resurrected", e)
	}
}

func TestRuntimeStateStopRefusesMissingForeignOrReboundControllerLock(t *testing.T) {
	for _, kind := range []string{"missing", "nonempty", "mode", "symlink", "hardlink", "directory", "rebound", "rebound-after-intent"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.drain(t, s)
			path := x.f.root.Name() + stateDir + "/controller.lock"
			mutate := func() error {
				switch kind {
				case "nonempty":
					return os.WriteFile(path, []byte("foreign"), 0600)
				case "mode":
					return os.Chmod(path, 0644)
				case "hardlink":
					return os.Link(path, path+".other")
				default:
					if e := os.Rename(path, path+".original"); e != nil {
						return e
					}
					switch kind {
					case "missing":
						return nil
					case "symlink":
						return os.Symlink(path+".original", path)
					case "directory":
						return os.Mkdir(path, 0700)
					default:
						return os.WriteFile(path, nil, 0600)
					}
				}
			}
			if kind == "rebound-after-intent" {
				x.f.hook = func(at string) error {
					if at == "runtime-stop-intent-durable" {
						return mutate()
					}
					return nil
				}
			} else if e := mutate(); e != nil {
				t.Fatal(e)
			}
			if _, e := x.stop(context.Background(), s, x.client); e == nil {
				t.Fatal("foreign current lock accepted")
			}
			if len(x.jobs) != 0 {
				t.Fatal("uncertain state inode reached stop jobs", x.jobs)
			}
			if kind == "missing" {
				if _, e := os.Lstat(path); !os.IsNotExist(e) {
					t.Fatal("missing state lock repaired", e)
				}
			}
		})
	}
}

func TestRuntimeStateKernelLockParserRequiresExactOriginalHolder(t *testing.T) {
	id := runtimeStateIdentity{LockDevice: unix.Mkdev(8, 1), LockInode: 99}
	good := "1: FLOCK ADVISORY WRITE 123 08:01:99 0 EOF\n"
	for _, kind := range []string{"valid", "foreign-file", "absent", "wrong-pid", "read", "posix", "ofd", "waiter", "offset", "partial", "duplicate", "bad-device"} {
		t.Run(kind, func(t *testing.T) {
			raw := good
			switch kind {
			case "foreign-file":
				raw = "2: POSIX ADVISORY WRITE 456 08:02:100 0 EOF\n" + good
			case "absent":
				raw = "2: FLOCK ADVISORY WRITE 456 08:02:100 0 EOF\n"
			case "wrong-pid":
				raw = strings.ReplaceAll(raw, "123", "124")
			case "read":
				raw = strings.ReplaceAll(raw, "WRITE", "READ")
			case "posix":
				raw = strings.ReplaceAll(raw, "FLOCK", "POSIX")
			case "ofd":
				raw = strings.ReplaceAll(raw, "FLOCK", "OFDLCK")
			case "waiter":
				raw = strings.ReplaceAll(raw, "1:", "1: ->")
			case "offset":
				raw = strings.ReplaceAll(raw, "0 EOF", "1 EOF")
			case "partial":
				raw = strings.TrimSuffix(raw, "\n")
			case "duplicate":
				raw += good
			case "bad-device":
				raw = strings.ReplaceAll(raw, "08:01:99", "08:xx:99")
			}
			e := stateKernelLockOwner([]byte(raw), id, 123)
			want := kind == "valid" || kind == "foreign-file"
			if (e == nil) != want {
				t.Fatal(kind, e)
			}
		})
	}
}

func TestRuntimeStateLockErrorOrRebindingNeverRetainsAcquiredFD(t *testing.T) {
	for _, kind := range []string{"error-cut", "lock-rebind", "root-rebind", "foreign-holder", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.drain(t, s)
			if _, e := x.stop(context.Background(), s, x.client); e != nil {
				t.Fatal(e)
			}
			path := x.f.root.Name() + stateDir
			var foreign *runtimeStateLease
			if kind == "foreign-holder" {
				var e error
				foreign, e = x.f.openRuntimeState()
				if e != nil {
					t.Fatal(e)
				}
				defer foreign.close()
				if e = acquireRuntimeState(foreign); e != nil {
					t.Fatal(e)
				}
			}
			x.f.hook = func(at string) error {
				if at != "runtime-state-locked" {
					return nil
				}
				switch kind {
				case "error-cut":
					return interrupted
				case "lock-rebind":
					if e := os.Rename(path+"/controller.lock", path+"/old.lock"); e != nil {
						return e
					}
					return os.WriteFile(path+"/controller.lock", nil, 0600)
				case "root-rebind":
					return os.Rename(path, path+".original")
				}
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				cancel()
			}
			if e := ownStateModel(ctx, x, s); e == nil {
				t.Fatal("uncertain state ownership accepted")
			}
			if s.state != nil {
				t.Fatal("failed stage retained state capability")
			}
			if kind == "error-cut" || kind == "cancel" {
				p, e := x.f.openRuntimeState()
				if e != nil {
					t.Fatal(e)
				}
				defer p.close()
				if e = acquireRuntimeState(p); e != nil {
					t.Fatal("failure leaked BSD lock", e)
				}
			}
			if kind == "foreign-holder" {
				other, e := x.f.openRuntimeState()
				if e != nil {
					t.Fatal(e)
				}
				defer other.close()
				if e = acquireRuntimeState(other); !errors.Is(e, unix.EWOULDBLOCK) {
					t.Fatal("foreign lock broken", e)
				}
			}
		})
	}
}

func TestRuntimeStateLegacyStopCannotGainStrongerStateAuthority(t *testing.T) {
	x := stopModel(t, "")
	s := x.scope(t)
	x.drain(t, s)
	if _, e := x.stop(context.Background(), s, x.client); e != nil {
		t.Fatal(e)
	}
	p, e := x.f.readRuntimeStop()
	if e != nil {
		t.Fatal(e)
	}
	p.Version, p.State = 1, nil
	for name, b := range map[string][]byte{"intent.json": encode(p), "stopped.json": encode(runtimeStopReceipt{Version: 1, Input: digest(encode(p))})} {
		if e = os.WriteFile(x.f.root.Name()+runtimeStopRoot+"/"+name, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if r, e := x.stop(context.Background(), s, nil); e != nil || !r.ExecutionStopped || len(x.jobs) != 2 {
		t.Fatal("legacy physical-only recovery changed", r, e)
	}
	if e = ownStateModel(context.Background(), x, s); !errors.Is(e, ErrConflict) {
		t.Fatal("v1 receipt upgraded without original binding", e)
	}
	after, e := x.f.readRuntimeStop()
	if e != nil || after.Version != 1 || after.State != nil {
		t.Fatal(fmt.Sprint(after), e)
	}
}
