package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

func TestCreationTimingSessionOpenSwitchAndReplay(t *testing.T) {
	b, _, d, _ := fixture(t, Options{}, nil)
	ctx := telemetry.WithCreationTrace(context.Background())
	first, err := b.Open(ctx, alpha, "timed-open", sandbox.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	openHeader := telemetry.CreationServerTiming(ctx)
	check := func(ctx context.Context) {
		t.Helper()
		header := telemetry.CreationServerTiming(ctx)
		for _, phase := range []string{"xa_core_admission", "xa_core_owner_commit", "xa_core_driver", "xa_core_ready_commit", "xa_session_intent_commit", "xa_session_prepared_commit", "xa_session_active_commit"} {
			if strings.Count(header, phase+";") != 1 {
				t.Fatal("missing/doubled actual phase", phase, header)
			}
		}
		if len(strings.Split(header, ", ")) != 7 || strings.Count(header, `desc="n1"`) != 7 {
			t.Fatal("unexpected observation", header)
		}
	}
	check(ctx)
	nextCtx := telemetry.WithCreationTrace(context.Background())
	second, err := b.Switch(nextCtx, alpha, first.ID, "timed-switch", SwitchRequest{ExpectedRevision: 1})
	if err != nil || second.Previous != first.Current || second.Revision != 2 {
		t.Fatal("switch semantics changed", second, err)
	}
	check(nextCtx)
	if telemetry.CreationServerTiming(ctx) != openHeader {
		t.Fatal("new call mutated completed request trace")
	}
	replayCtx := telemetry.WithCreationTrace(context.Background())
	if _, err := b.Switch(replayCtx, alpha, first.ID, "timed-switch", SwitchRequest{ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if telemetry.CreationServerTiming(replayCtx) != "" || d.calls.Load() != 2 {
		t.Fatal("replay invented new preparation/commit")
	}
}

func TestCreationTimingSessionFailureDoesNotInventCommitOrRepairBinding(t *testing.T) {
	b, _, d, _ := fixture(t, Options{}, nil)
	first := open(t, b, "first")
	d.fail.Store(true)
	ctx := telemetry.WithCreationTrace(context.Background())
	if _, err := b.Switch(ctx, alpha, first.ID, "failed-switch", SwitchRequest{ExpectedRevision: 1}); err == nil {
		t.Fatal("driver error hidden")
	}
	header := telemetry.CreationServerTiming(ctx)
	if !strings.Contains(header, "xa_core_driver;") || !strings.Contains(header, "xa_session_intent_commit;") || strings.Contains(header, "xa_session_prepared_commit;") || strings.Contains(header, "xa_session_active_commit;") || strings.Contains(header, "xa_core_ready_commit;") {
		t.Fatal("failure fabricated later successful work", header)
	}
	view, has, err := b.Get(alpha.TenantID, first.ID)
	if err != nil || !has || view.Revision != first.Revision || view.Current != first.Current {
		t.Fatal("observer changed abort binding", view, has, err)
	}
	if _, err := b.Switch(context.Background(), alpha, first.ID, "failed-switch", SwitchRequest{ExpectedRevision: 1}); !errors.Is(err, ErrGone) {
		t.Fatal("failed key unexpectedly reusable", err)
	}
}
