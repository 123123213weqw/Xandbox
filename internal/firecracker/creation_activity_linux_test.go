//go:build linux

package firecracker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

// No root, cgroup setup, VM or fake check hook: use the real gate and a
// deliberately invalid node anchor for the existing fail-closed return path.
func TestCreationActivityRealNodePermitCancellationAndCheckFailure(t *testing.T) {
	n := &nodeEnvelope{preparing: newPrepareGate(1)}
	if e := n.preparing.acquire(context.Background()); e != nil {
		t.Fatal(e)
	}
	metrics := &telemetry.Registry{}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := telemetry.WithCreationTraceKind(parent, metrics, telemetry.CreationSessionSwitch)
	defer telemetry.EndCreationTrace(ctx)
	done := make(chan error, 1)
	held, joined := true, false
	go func() { done <- n.acquirePrepare(ctx) }()
	defer func() {
		cancel()
		if held {
			n.preparing.release()
		}
		if joined {
			return
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned waiter not returned")
		}
	}()
	until := time.Now().Add(time.Second)
	for !strings.Contains(string(metrics.Render(telemetry.Gauges{})), `xandbox_creation_phases_active{operation="session_switch",phase="xa_driver_permit_wait"} 1`+"\n") {
		if time.Now().After(until) {
			t.Fatal("actual node wait has no activity observation")
		}
		time.Sleep(time.Millisecond)
	}
	text := string(metrics.Render(telemetry.Gauges{}))
	if !strings.Contains(text, `xandbox_creation_phases_active{operation="session_switch",phase="xa_driver_node_check"} 0`+"\n") {
		t.Fatal("node validation claimed before permit")
	}
	cancel()
	select {
	case e := <-done:
		joined = true
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("real wait did not cancel")
	}
	if len(n.preparing.tokens) != 1 {
		t.Fatal("canceled observer changed permit ownership")
	}
	if !strings.Contains(string(metrics.Render(telemetry.Gauges{})), `xandbox_creation_phases_active{operation="session_switch",phase="xa_driver_permit_wait"} 0`+"\n") {
		t.Fatal("actual canceled wait did not end")
	}
	// Return the held permit before exercising the existing node rejection.
	n.preparing.release()
	held = false
	rawCtx := telemetry.WithCreationTraceKind(context.Background(), metrics, telemetry.CreationRaw)
	defer telemetry.EndCreationTrace(rawCtx)
	if e := n.acquirePrepare(rawCtx); e == nil || len(n.preparing.tokens) != 0 {
		t.Fatal("invalid anchor accepted or permit leaked", e)
	}
	text = string(metrics.Render(telemetry.Gauges{}))
	for _, phase := range []string{"xa_driver_permit_wait", "xa_driver_node_check"} {
		if !strings.Contains(text, `xandbox_creation_phases_active{operation="raw_create",phase="`+phase+`"} 0`+"\n") {
			t.Fatal("node rejection leaked observed phase")
		}
	}
}
