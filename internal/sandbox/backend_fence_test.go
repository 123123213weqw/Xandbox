package sandbox

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fencedDriver struct {
	Driver
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (d *fencedDriver) Exec(ctx context.Context, ref Ref, req ExecRequest, limit int) (Output, error) {
	d.once.Do(func() { close(d.entered) })
	select {
	case <-d.release:
		return Output{}, ErrBackendFenced
	case <-ctx.Done():
		return Output{}, errors.Join(ErrBackendFenced, ctx.Err())
	}
}

func TestBackendFenceSchedulesReclaimAndPreservesExplicitStop(t *testing.T) {
	for _, explicitStop := range []bool{false, true} {
		t.Run(map[bool]string{false: "spontaneous", true: "explicit-stop"}[explicitStop], func(t *testing.T) {
			var backend *fencedDriver
			m, _, _ := setup(t, Options{}, func(d Driver) Driver {
				backend = &fencedDriver{Driver: d, entered: make(chan struct{}), release: make(chan struct{})}
				return backend
			})
			r := create(t, m, CreateRequest{})
			_, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}})
			if err != nil {
				t.Fatal(err)
			}
			<-backend.entered
			if explicitStop {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				stopped, err := m.Stop(ctx, r.Ref)
				if err != nil || stopped.State != Stopped || stopped.DeleteRequested {
					t.Fatalf("stop became deletion: %+v %v", stopped, err)
				}
				if _, err := m.Destroy(r.Ref); err != nil {
					t.Fatal(err)
				}
			} else {
				close(backend.release)
			}
			waitState(t, m, r.ID, Destroyed)
		})
	}
}

func TestSeparateLifecycleBudgetsOverrideLegacyDefault(t *testing.T) {
	m, _, _ := setup(t, Options{OperationTimeout: time.Nanosecond, PrepareTimeout: time.Second,
		StopTimeout: time.Second, CleanupTimeout: time.Second}, nil)
	r := create(t, m, CreateRequest{})
	stopped, err := m.Stop(context.Background(), r.Ref)
	if err != nil || stopped.State != Stopped {
		t.Fatalf("separate Stop budget not applied: %v", err)
	}
	if _, err := m.Destroy(r.Ref); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, r.ID, Destroyed)
}
