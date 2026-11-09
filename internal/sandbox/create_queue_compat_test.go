package sandbox

import (
	"context"
	"errors"
	"testing"
)

func TestCreateCapacityQueueRawOnlyKeepsFailFastAdmission(t *testing.T) {
	m, _ := queueOrderingManager(t)
	create(t, m, CreateRequest{})
	ctx, cancel := queueCaller(t)
	done := startQueuedCreate(func() (Record, error) {
		return m.CreateScoped(ctx, Owner{TenantID: "alpha", MaxInstances: 1}, "raw-overflow", CreateRequest{})
	})
	var reply *queuedCreateReply
	queued := false
	eventually(t, func() bool {
		select {
		case v := <-done:
			reply = &v
			return true
		default:
			queued = m.Metrics().CreateQueued != 0
			return queued
		}
	})
	if queued {
		cancel()
		queuedReply(t, done, context.Canceled)
		t.Fatal("raw-only capacity refusal unexpectedly queued; breaks existing bounded raw protocols")
	}
	if reply == nil || !errors.Is(reply.err, ErrCapacity) || reply.record.Ref != (Ref{}) || ctx.Err() != nil || m.Metrics().CreateQueued != 0 || m.Metrics().Records != 1 {
		t.Fatal("raw-only overload no longer fails before reservation")
	}
}
