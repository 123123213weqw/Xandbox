package sandbox

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

// No filesystem/VM resources: these are timing-boundary/fencing mechanisms,
// not claims about disk speed or KVM execution.
type creationTimingStore struct {
	failState State
	failed    atomic.Bool
}

func (*creationTimingStore) Load() ([]Record, error) { return nil, nil }
func (s *creationTimingStore) Save(r Record) error {
	if r.State == s.failState && s.failed.CompareAndSwap(false, true) {
		return errors.New("injected commit failure")
	}
	return nil
}

type creationTimingDriver struct {
	queueOrderingDriver
	fail     bool
	observed atomic.Bool
}

func (d *creationTimingDriver) Prepare(ctx context.Context, ref Ref, p Preparation) error {
	d.observed.Store(strings.Contains(telemetry.CreationServerTiming(ctx), "xa_core_owner_commit;"))
	if d.fail {
		return errors.New("injected driver failure")
	}
	return d.queueOrderingDriver.Prepare(ctx, ref, p)
}

func TestCreationTimingCoreBoundariesAndFailures(t *testing.T) {
	for _, test := range []struct {
		name       string
		failState  State
		failDriver bool
		phases     []string
	}{
		{"success", "", false, []string{"xa_core_admission", "xa_core_owner_commit", "xa_core_driver", "xa_core_ready_commit"}},
		{"owner commit", Creating, false, []string{"xa_core_admission", "xa_core_owner_commit"}},
		{"driver", "", true, []string{"xa_core_admission", "xa_core_owner_commit", "xa_core_driver"}},
		{"ready commit", Ready, false, []string{"xa_core_admission", "xa_core_owner_commit", "xa_core_driver", "xa_core_ready_commit"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := &creationTimingDriver{fail: test.failDriver}
			m, err := NewManager(&creationTimingStore{failState: test.failState}, d, Options{MaxInstances: 1, ReapInterval: time.Millisecond})
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
			ctx := telemetry.WithCreationTrace(context.Background())
			r, err := m.CreateScoped(ctx, Owner{TenantID: "alpha", MaxInstances: 1}, "timing-test", CreateRequest{})
			if (err == nil) != (test.name == "success") {
				t.Fatal("observer changed outcome", r.State, err)
			}
			parts := strings.Split(telemetry.CreationServerTiming(ctx), ", ")
			if len(parts) != len(test.phases) {
				t.Fatal("missing/extra actual phases", parts)
			}
			for i, phase := range test.phases {
				if !strings.HasPrefix(parts[i], phase+";") || !strings.HasSuffix(parts[i], `;desc="n1"`) {
					t.Fatal("wrong phase", parts[i])
				}
			}
			if test.failState != Creating && !d.observed.Load() {
				t.Fatal("driver did not receive request observer through original operation context")
			}
			if err == nil {
				refused := telemetry.WithCreationTrace(context.Background())
				if _, err := m.CreateScoped(refused, Owner{TenantID: "alpha", MaxInstances: 1}, "refused", CreateRequest{}); err != ErrCapacity {
					t.Fatal("raw overload policy changed", err)
				}
				if parts := strings.Split(telemetry.CreationServerTiming(refused), ", "); len(parts) != 1 || !strings.HasPrefix(parts[0], "xa_core_admission;") {
					t.Fatal("unallocated refusal fabricated prepare/commit", parts)
				}
			}
		})
	}
}

func TestCreationTimingCanceledCapacityWaitNeverReportsPrepare(t *testing.T) {
	m, _ := queueOrderingManager(t)
	if _, err := m.CreateScoped(context.Background(), Owner{TenantID: "alpha", MaxInstances: 1}, "first", CreateRequest{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(telemetry.WithCreationTrace(context.Background()))
	defer cancel()
	permit := NewAdmission(func(Ref) bool { return true })
	done := startQueuedCreate(func() (Record, error) {
		return m.CreateManagedScoped(ctx, Owner{TenantID: "beta", MaxInstances: 1}, "waiting", CreateRequest{}, permit, func(Ref) {})
	})
	waitCreateQueued(t, m, 1, done)
	if telemetry.CreationServerTiming(ctx) != "" {
		t.Fatal("unfinished admission reported a completed zero wait")
	}
	cancel()
	queuedReply(t, done, context.Canceled)
	if header := telemetry.CreationServerTiming(ctx); !strings.HasPrefix(header, "xa_core_admission;") || strings.Contains(header, ",") {
		t.Fatal("cancellation invented downstream work", header)
	}
}
