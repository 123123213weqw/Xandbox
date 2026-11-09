package sandbox

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

// Self-contained so the IDENTICAL control can run on the released main, which
// has no capacity queue. It is memory-only, not a real-backend latency test.
type futureWaitStore struct{}

func (futureWaitStore) Load() ([]Record, error) { return nil, nil }
func (futureWaitStore) Save(Record) error       { return nil }

type futureWaitDriver struct{ calls atomic.Int32 }

func (*futureWaitDriver) Name() string           { return "mock" }
func (*futureWaitDriver) RefreshLease(Ref) error { return nil }
func (*futureWaitDriver) RevokeLease(Ref) error  { return nil }
func (d *futureWaitDriver) Prepare(ctx context.Context, _ Ref, _ Preparation) error {
	d.calls.Add(1)
	return ctx.Err()
}
func (*futureWaitDriver) Exec(context.Context, Ref, ExecRequest, int) (Output, error) {
	return Output{}, ErrNotReady
}
func (*futureWaitDriver) Stop(ctx context.Context, _ Ref) error    { return ctx.Err() }
func (*futureWaitDriver) Cleanup(ctx context.Context, _ Ref) error { return ctx.Err() }

func TestManagedFutureCapacityProgressAfterDurableRelease(t *testing.T) {
	driver := &futureWaitDriver{}
	m, err := NewManager(futureWaitStore{}, driver, Options{MaxInstances: 1, ReapInterval: time.Millisecond, RetryDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	owner := Owner{TenantID: "alpha", MaxInstances: 1}
	held, err := m.CreateScoped(context.Background(), owner, "held", CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type reply struct {
		record Record
		err    error
	}
	done := make(chan reply, 1)
	var captured atomic.Int32
	go func() {
		r, err := m.CreateManagedScoped(ctx, owner, "next", CreateRequest{}, NewAdmission(func(Ref) bool { return true }), func(Ref) { captured.Add(1) })
		done <- reply{r, err}
	}()
	// Pair the ordinary queue observation with early error detection. On old
	// main the call fails here, BEFORE any release. Absence of a gauge alone
	// is not used as a proof of successful waiting or an elapsed-time failure.
	eventually(t, func() bool {
		select {
		case v := <-done:
			t.Fatalf("managed call refused before capacity release: %v", v.err)
		default:
		}
		return strings.Contains(string((*telemetry.Registry)(nil).Render(m.Metrics())), "xandbox_create_queued 1\n")
	})
	if driver.calls.Load() != 1 || captured.Load() != 0 || m.Metrics().Allocated != 1 || m.Metrics().Records != 1 {
		t.Fatal("waiting allocated another generation")
	}
	if _, err = m.Destroy(held.Ref); err != nil {
		t.Fatal(err)
	}
	select {
	case v := <-done:
		if v.err != nil || v.record.State != Ready || v.record.Ref == held.Ref || driver.calls.Load() != 2 || captured.Load() != 1 {
			t.Fatal("waiting did not progress exactly once", v.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("managed waiter did not settle")
	}
}
