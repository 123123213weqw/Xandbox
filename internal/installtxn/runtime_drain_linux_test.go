//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type drainTestStore struct {
	nodecontrol.Store
	check func() error
}

func (s drainTestStore) Save(old, next nodecontrol.State) error {
	if s.check != nil {
		if e := s.check(); e != nil {
			return e
		}
	}
	return s.Store.Save(old, next)
}

// Real file store + controller + Unix RPC in the Go test process. Installation,
// executable bytes and manager are a shadow/model, NOT a daemon/cgroup proof.
// Short owned roots keep the real Unix path within Linux sun_path bounds.
func drainModel(t *testing.T, check func(*filesystem) error) (*filesystem, transaction, *nodecontrol.PinnedClient, *nodecontrol.Controller) {
	t.Helper()
	original, p, m := fixture(t)
	short, e := os.MkdirTemp("", "xb-dr-")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(short); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(original.root.Name(), short); e != nil {
		t.Fatal(e)
	}
	root, e := os.Open(short)
	if e != nil {
		t.Fatal(e)
	}
	f := &filesystem{root: root}
	t.Cleanup(func() {
		if dir, e := f.directory(childRoot); e == nil {
			dir.Chmod(0700)
			dir.Close()
		}
		root.Close()
		if e := os.RemoveAll(short); e != nil {
			t.Error(e)
		}
	})
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	store, e := nodecontrol.OpenStore(short + stateDir)
	if e != nil {
		t.Fatal(e)
	}
	wrapper := drainTestStore{Store: store}
	if check != nil {
		wrapper.check = func() error { return check(f) }
	}
	controller, e := nodecontrol.New(wrapper, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	s, e := nodecontrol.Start(short+stateDir, controller, func() sandbox.Stats { return sandbox.Stats{Capacity: 4, Active: 1} })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Close(ctx)
		controller.Close(ctx)
	})
	client, e := nodecontrol.NewPinnedClient(short+stateDir, os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	return f, tx, client, controller
}
func drainApply(ctx context.Context, f *filesystem, tx transaction, client *nodecontrol.PinnedClient) (runtimeDrainResult, error) {
	return f.runtimeDrainAdmission(ctx, digest(encode(tx)), runtimeReq("b"), client)
}

func TestRuntimeDrainRealUnixCASPersistsAndNeverCertifiesStop(t *testing.T) {
	f, tx, client, c := drainModel(t, func(f *filesystem) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		file, e := f.existingLock(ctx, true)
		if e != nil {
			return errors.New("RPC held install flock")
		}
		file()
		ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		op, e := f.operationLock(ctx, false)
		if e == nil {
			op()
			return errors.New("RPC lost operation EX")
		}
		if !errors.Is(e, context.DeadlineExceeded) {
			return e
		}
		return nil
	})
	before := runtimeProtectedBytes(t, f, tx)
	r, e := drainApply(context.Background(), f, tx, client)
	if e != nil || !r.AdmissionDrained || !r.WasOpen || r.Revision != 2 || r.AcceptedWorkComplete || r.StopObserved || r.ResourcesReclaimed || r.ActivationAllowed {
		t.Fatal(r, e)
	}
	if c.Status().AdmissionOpen || c.Status().Committed.Revision != 2 {
		t.Fatal("real controller not drained")
	}
	store, e := nodecontrol.OpenStore(f.root.Name() + stateDir)
	if e != nil {
		t.Fatal(e)
	}
	state, e := store.Load()
	if e != nil || state != c.Status().Committed {
		t.Fatal("drain not durable", e)
	}
	again, e := drainApply(context.Background(), f, tx, client)
	if e != nil || again != r {
		t.Fatal("exact retry advanced authority", again, e)
	}
	unchangedRuntimeProtected(t, f, before)
	for _, v := range runtimeSubset(tx) {
		if e = f.verify(context.Background(), v); e != nil {
			t.Fatal("drain changed runtime files", e)
		}
	}
	if _, e = f.startupFilesLocked(context.Background()); e == nil {
		t.Fatal("pending update namespace allowed startup")
	}
	if _, e = runtimeApply(context.Background(), f, tx, 0, runtimeReq("c"), "forward", nil); !errors.Is(e, ErrInventory) {
		t.Fatal("drain composed as stop/reclaim proof", e)
	}
}

func TestRuntimeDrainPreexistingDrainNeverResumesOrAdvances(t *testing.T) {
	f, tx, client, c := drainModel(t, nil)
	before := c.Status().Committed
	_, e := c.Change(context.Background(), nodecontrol.ModeDrained, nodecontrol.Command{Version: 1, Epoch: before.Epoch, ExpectedRevision: before.Revision, RequestID: runtimeReq("e")})
	if e != nil {
		t.Fatal(e)
	}
	before = c.Status().Committed
	for i := 0; i < 2; i++ {
		r, e := drainApply(context.Background(), f, tx, client)
		if e != nil || !r.AdmissionDrained || r.WasOpen || c.Status().Committed != before {
			t.Fatal(r, e)
		}
	}
}

var drainCuts = []string{"runtime-drain-intent-written", "runtime-drain-intent-synced", "runtime-drain-intent-renamed", "runtime-drain-intent-durable", "runtime-drain-before-rpc", "runtime-drain-after-rpc", "runtime-drain-receipt-written", "runtime-drain-receipt-synced", "runtime-drain-receipt-renamed", "runtime-drain-receipt-durable"}

func TestRuntimeDrainWriteAheadCutsRecoverSameCommand(t *testing.T) {
	for _, cut := range drainCuts {
		t.Run(cut, func(t *testing.T) {
			f, tx, client, c := drainModel(t, nil)
			hit := false
			f.hook = func(at string) error {
				if at == cut && !hit {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := drainApply(context.Background(), f, tx, client); !errors.Is(e, interrupted) || !hit {
				t.Fatal("drain cut not reached", e)
			}
			f.hook = nil
			fresh, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer fresh.Close()
			f = &filesystem{root: fresh}
			r, e := drainApply(context.Background(), f, tx, client)
			if e != nil || !r.AdmissionDrained || r.Revision != 2 || c.Status().Committed.Revision != 2 {
				t.Fatal("lost reply duplicated or lost drain", r, e)
			}
			if r.StopObserved || r.ResourcesReclaimed || r.ActivationAllowed {
				t.Fatal("drain inflated into lifecycle acceptance")
			}
		})
	}
}

func TestRuntimeDrainForeignResumeAndNewRequestsNeverOverwriteIntent(t *testing.T) {
	f, tx, client, c := drainModel(t, nil)
	if _, e := drainApply(context.Background(), f, tx, client); e != nil {
		t.Fatal(e)
	}
	before := runtimeShadowBytes(t, f)
	if _, e := f.runtimeDrainAdmission(context.Background(), digest(encode(tx)), runtimeReq("c"), client); !errors.Is(e, ErrConflict) {
		t.Fatal("different request adopted journal", e)
	}
	if !bytes.Equal(encode(before), encode(runtimeShadowBytes(t, f))) {
		t.Fatal("conflict mutated files")
	}
	s := c.Status().Committed
	_, e := c.Change(context.Background(), nodecontrol.ModeOpen, nodecontrol.Command{Version: 1, Epoch: s.Epoch, ExpectedRevision: s.Revision, RequestID: runtimeReq("e")})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = drainApply(context.Background(), f, tx, client); !errors.Is(e, ErrConflict) {
		t.Fatal("foreign resume silently drained or receipt reused", e)
	}
	if !c.Status().AdmissionOpen || c.Status().Committed.Revision != 3 {
		t.Fatal("foreign authority rewound")
	}
}

func TestRuntimeDrainUnknownStateAndWrongRootRefuseWithoutRPC(t *testing.T) {
	for _, kind := range []string{"unknown", "receipt-without-intent", "malformed-intent", "different-process", "protected-drift", "closed-client", "wrong-root"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, client, c := drainModel(t, nil)
			switch kind {
			case "closed-client":
				client.Close()
			case "wrong-root":
				other, e := os.MkdirTemp("", "xb-dr-other-")
				if e != nil {
					t.Fatal(e)
				}
				defer os.RemoveAll(other)
				client, e = nodecontrol.NewPinnedClient(other, os.Getpid())
				if e != nil {
					t.Fatal(e)
				}
				defer client.Close()
			case "protected-drift":
				if e := os.WriteFile(f.root.Name()+Root+"/auth.json", []byte("external authority"), 0600); e != nil {
					t.Fatal(e)
				}
			default:
				if e := f.mkdir(runtimeDrainRoot, 0700); e != nil {
					t.Fatal(e)
				}
				name := map[string]string{"unknown": "foreign", "receipt-without-intent": "drain.json", "malformed-intent": "intent.json", "different-process": "intent.json"}[kind]
				raw := []byte("preserve unknown bytes\n")
				if kind == "different-process" {
					id := client.Identity()
					id.StartTicks++
					raw = encode(runtimeDrainIntent{Version: 1, Base: digest(encode(tx)), Request: runtimeReq("b"), Process: id, Before: c.Status().Committed})
				}
				if e := os.WriteFile(f.root.Name()+runtimeDrainRoot+"/"+name, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := runtimeShadowBytes(t, f)
			if _, e := drainApply(context.Background(), f, tx, client); e == nil {
				t.Fatal("uncertain input accepted")
			}
			if c.Status().Committed.Revision != 1 || !c.Status().AdmissionOpen {
				t.Fatal("invalid input sent mutation")
			}
			if !bytes.Equal(encode(before), encode(runtimeShadowBytes(t, f))) {
				t.Fatal("uncertain state repaired or overwritten")
			}
		})
	}
}

func TestRuntimeDrainInspectionBaseRejectsEvenEmptyMaintenanceNamespace(t *testing.T) {
	f, tx, _, _ := drainModel(t, nil)
	p := UpdateInspectionPlan{InstallCommitSHA256: digest(encode(tx)), RetainedRelease: tx.Plan.Release, ReleaseRevision: tx.Plan.ReleaseRevision + 1}
	if _, e := f.inspectionBase(context.Background(), p); e != nil {
		t.Fatal("clean baseline", e)
	}
	if e := f.mkdir(runtimeDrainRoot, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := f.inspectionBase(context.Background(), p); !errors.Is(e, ErrInventory) {
		t.Fatal("pending drain certified as clean inventory", e)
	}
}

func TestRuntimeDrainInconsistentReceiptsRefuseBeforeMutation(t *testing.T) {
	for _, kind := range []string{"bad-final", "bad-prefix", "premature-final", "premature-prefix", "intent-and-scratch"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, client, c := drainModel(t, nil)
			f.hook = func(at string) error {
				if at == "runtime-drain-before-rpc" {
					return interrupted
				}
				return nil
			}
			if _, e := drainApply(context.Background(), f, tx, client); !errors.Is(e, interrupted) {
				t.Fatal(e)
			}
			f.hook = nil
			p, e := f.runtimeDrainReadIntent()
			if e != nil {
				t.Fatal(e)
			}
			raw := encode(runtimeDrainReceipt{Version: 1, Input: digest(encode(p)), After: drainedRuntimeState(p)})
			name := "drain.json"
			switch kind {
			case "bad-final":
				raw = []byte("unknown authority")
			case "bad-prefix":
				name = ".drain.json.next"
				raw = []byte("unknown prefix")
			case "premature-prefix":
				name = ".drain.json.next"
				raw = raw[:len(raw)/2]
			case "intent-and-scratch":
				name = ".intent.json.next"
				raw = encode(p)
			}
			if e = os.WriteFile(f.root.Name()+runtimeDrainRoot+"/"+name, raw, 0600); e != nil {
				t.Fatal(e)
			}
			before := runtimeShadowBytes(t, f)
			if _, e = drainApply(context.Background(), f, tx, client); e == nil {
				t.Fatal("inconsistent receipt accepted")
			}
			if c.Status().Committed.Revision != 1 || !c.Status().AdmissionOpen {
				t.Fatal("unknown receipt triggered drain mutation")
			}
			if !bytes.Equal(encode(before), encode(runtimeShadowBytes(t, f))) {
				t.Fatal("unknown receipt overwritten/repaired")
			}
		})
	}
}
