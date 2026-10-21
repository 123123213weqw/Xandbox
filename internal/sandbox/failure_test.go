package sandbox

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type failingStore struct {
	Store
	failReady     atomic.Bool
	failDestroyed atomic.Bool
}

func (s *failingStore) Save(r Record) error {
	if (r.State == Ready && s.failReady.Load()) || (r.State == Destroyed && s.failDestroyed.Load()) {
		return fmt.Errorf("injected ledger failure")
	}
	return s.Store.Save(r)
}

func faultManager(t *testing.T) (*Manager, *failingStore) {
	t.Helper()
	base := t.TempDir()
	fileStore, err := NewFileStore(filepath.Join(base, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	store := &failingStore{Store: fileStore}
	driver, err := NewMockDriver(filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(store, driver, Options{MaxInstances: 1, ReapInterval: time.Millisecond, RetryDelay: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.failReady.Store(false)
		store.failDestroyed.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return m, store
}

func TestReadyRequiresDurableCommit(t *testing.T) {
	m, store := faultManager(t)
	store.failReady.Store(true)
	r, err := m.Create(context.Background(), CreateRequest{})
	if err == nil || r.State == Ready {
		t.Fatalf("non-durable instance was exposed: %+v %v", r, err)
	}
	if _, err := m.Exec(r.ID, ExecRequest{Generation: r.Generation, Argv: []string{"echo"}}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("non-durable instance accepted work: %v", err)
	}
	waitState(t, m, r.ID, Destroyed)
}

func TestCapacityRequiresDurableDestroyedCommit(t *testing.T) {
	m, store := faultManager(t)
	r := create(t, m, CreateRequest{})
	store.failDestroyed.Store(true)
	if _, err := m.Destroy(r.Ref); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		current, _ := m.Get(r.ID)
		return current.State == Reclaiming && current.LastError != ""
	})
	if _, err := m.Create(context.Background(), CreateRequest{}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity returned before durable reclamation: %v", err)
	}
	store.failDestroyed.Store(false)
	waitState(t, m, r.ID, Destroyed)
	eventually(t, func() bool { return m.Stats().Active == 0 })
	create(t, m, CreateRequest{})
}

func TestConcurrentCreateAndClose(t *testing.T) {
	for range 10 {
		m, _, _ := setup(t, Options{}, nil)
		created := make(chan struct{})
		go func() {
			defer close(created)
			_, err := m.Create(context.Background(), CreateRequest{})
			if err != nil && !errors.Is(err, ErrClosing) {
				// Fenced creation can also fail after its reservation was accepted.
				t.Logf("creation fenced during shutdown: %v", err)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := m.Close(ctx)
		cancel()
		<-created
		if err != nil {
			t.Fatal(err)
		}
		if m.Stats().Active != 0 {
			t.Fatal("shutdown leaked an in-flight creation")
		}
	}
}
