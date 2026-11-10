//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestRuntimeScopeSpansRepeatedDrainWithoutLockReacquisition(t *testing.T) {
	f, tx, client, _ := drainModel(t, nil)
	s, e := f.beginRuntimeScope(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		r, e := s.drain(ctx, digest(encode(tx)), runtimeReq("b"), client)
		if e != nil || r.Revision != 2 || !r.AdmissionDrained {
			t.Fatal(r, e)
		}
	}
	blocked, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if done, e := f.operationLock(blocked, false); e == nil {
		done()
		t.Fatal("outer operation lease not retained")
	} else if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	file, e := f.existingLock(ctx, true)
	if e != nil {
		t.Fatal("scope held unnecessary file flock", e)
	}
	file()
	s.close()
	if _, e = s.drain(ctx, digest(encode(tx)), runtimeReq("b"), client); !errors.Is(e, ErrConflict) {
		t.Fatal("closed scope reused", e)
	}
	if done, e := f.operationLock(ctx, false); e != nil {
		t.Fatal("scope did not release", e)
	} else {
		done()
	}
}
func TestRuntimeScopeMissingOrReboundLockNeverRepaired(t *testing.T) {
	for _, kind := range []string{"missing", "rebound", "nonempty"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, c, control := drainModel(t, nil)
			s, e := f.beginRuntimeScope(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer s.close()
			path := f.root.Name() + Root + "/.lock"
			switch kind {
			case "missing":
				e = os.Remove(path)
			case "rebound":
				e = os.Rename(path, path+".old")
				if e == nil {
					e = os.WriteFile(path, nil, 0600)
				}
			case "nonempty":
				e = os.WriteFile(path, []byte("foreign"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.drain(context.Background(), digest(encode(tx)), runtimeReq("b"), c); e == nil {
				t.Fatal("lost scope adopted lock")
			}
			if control.Status().Committed.Revision != 1 {
				t.Fatal("corrupt lock reached RPC")
			}
			if kind == "missing" {
				if yes, _ := f.exists(Root + "/.lock"); yes {
					t.Fatal("lock recreated")
				}
			}
		})
	}
}
func TestRuntimeScopeCloseWaitsForStageAndCancellationHasNoEffects(t *testing.T) {
	f, _, _, _ := drainModel(t, nil)
	s, e := f.beginRuntimeScope(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if e = s.run(canceled, func(*filesystem) error { called = true; return nil }); !errors.Is(e, context.Canceled) || called {
		t.Fatal(e)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.run(context.Background(), func(*filesystem) error { close(entered); <-release; return nil })
	}()
	<-entered
	closed := make(chan struct{})
	go func() { s.close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("closed a live stage lease")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	<-closed
}
