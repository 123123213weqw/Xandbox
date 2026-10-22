package session

import (
	"context"
	"github.com/123123213weqw/Xandbox/internal/telemetry"
	"strings"
	"testing"
	"time"
)

func TestSessionMetricsAreBoundedAndNeverWaitForJournalOrEntry(t *testing.T) {
	r := &telemetry.Registry{}
	b, _, _, _ := fixture(t, Options{Metrics: r}, nil)
	first := open(t, b, "metrics-first")
	if _, err := b.Switch(context.Background(), alpha, first.ID, "metrics-next", SwitchRequest{ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	e, _ := b.lookup(alpha.TenantID, first.ID)
	b.mu.Lock()
	e.mu.Lock()
	done := make(chan struct{})
	go func() {
		records, capacity := b.Metrics()
		if records != 1 || capacity != 1000 {
			t.Error(records, capacity)
		}
		r.Render(telemetry.Gauges{Sessions: records})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("metrics waited for session lock")
	}
	e.mu.Unlock()
	b.mu.Unlock()
	s := string(r.Render(telemetry.Gauges{}))
	for _, op := range []string{"candidate_ready_offset", "admission_revoked_offset", "fence_to_commit", "route_published_offset"} {
		if !strings.Contains(s, `xandbox_operation_seconds_count{operation="`+op+`",outcome="success"} 2`) {
			t.Fatal("phase samples must include open and switch", op)
		}
	}
	for _, secret := range []string{first.ID, first.Current.ID, first.Current.Generation, "metrics-first", "alpha"} {
		if strings.Contains(s, secret) {
			t.Fatal("private field exported")
		}
	}
}
