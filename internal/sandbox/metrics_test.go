package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

func TestMetricsDoNotAcquireAnyLifecycleLock(t *testing.T) {
	r := &telemetry.Registry{}
	m, _, _ := setup(t, Options{Metrics: r, MaxInstances: 2}, nil)
	vm := create(t, m, CreateRequest{})
	i, _ := m.lookup(vm.ID)
	m.mu.Lock()
	m.workMu.Lock()
	i.mu.Lock()
	done := make(chan telemetry.Gauges, 1)
	go func() { g := m.Metrics(); r.Render(g); done <- g }()
	var g telemetry.Gauges
	select {
	case g = <-done:
	case <-time.After(time.Second):
		t.Error("metrics blocked on lifecycle lock")
	}
	i.mu.Unlock()
	m.workMu.Unlock()
	m.mu.Unlock()
	if g.Allocated != 1 || g.Records != 1 {
		t.Fatal(g)
	}
	if _, err := m.Stop(context.Background(), vm.Ref); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Destroy(vm.Ref); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, vm.ID, Destroyed)
	eventually(t, func() bool { return m.Metrics().Allocated == 0 })
	s := string(r.Render(m.Metrics()))
	for _, op := range []string{"create_call", "stop_attempt", "cleanup_attempt"} {
		if !strings.Contains(s, `xandbox_operation_seconds_count{operation="`+op+`",outcome="success"} 1`) {
			t.Fatal("missing successful operation", op)
		}
	}
	if m.Metrics().Records != 1 {
		t.Fatal("tombstone not counted")
	}
}
