package nodecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const runtimeResultsClosePath = maintenancePath + "/runtime-results-close"

// Only a pinned original incarnation can accept/observe closure. This result is
// live tracked-runtime closure, never full host reclaim or a durable receipt.
func (c *PinnedClient) RuntimeResultsClose(ctx context.Context, record MaintenanceRecord, begin bool) (RuntimeResultsCloseReply, error) {
	var zero RuntimeResultsCloseReply
	if c == nil || c.client == nil || c.client.live == nil {
		return zero, ErrProcessPin
	}
	if !record.Valid() {
		return zero, ErrInvalid
	}
	if e := c.client.live(); e != nil {
		return zero, e
	}
	op := "status"
	if begin {
		op = "begin"
	}
	data, _ := json.Marshal(RuntimeResultsCloseRequest{Version: 2, Operation: op, Maintenance: record.Request})
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://node.local"+runtimeResultsClosePath, bytes.NewReader(data))
	if e != nil {
		return zero, e
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := c.client.http.Do(r)
	if e != nil {
		return zero, e
	}
	defer response.Body.Close()
	b, e := io.ReadAll(io.LimitReader(response.Body, MaxReplyBytes+1))
	if e != nil {
		return zero, e
	}
	if len(b) > MaxReplyBytes {
		return zero, errors.New("result-bound runtime close reply too large")
	}
	if e = c.client.live(); e != nil {
		return zero, e
	}
	if response.StatusCode != 200 {
		if response.StatusCode == 404 || response.StatusCode == 501 {
			return zero, ErrRuntimeCloseUnsupported
		}
		var failure controlError
		if strictjson.Decode(b, &failure) != nil {
			return zero, errors.New("invalid result-bound runtime close failure")
		}
		switch failure.Code {
		case "MAINTENANCE":
			return zero, ErrMaintenance
		case "BUSY":
			return zero, ErrBusy
		case "PERSISTENCE_FENCED":
			return zero, ErrFenced
		case "CLOSED":
			return zero, ErrClosed
		default:
			return zero, errors.New("result-bound runtime close request refused")
		}
	}
	var reply RuntimeResultsCloseReply
	if strictjson.Decode(b, &reply) != nil || !reply.valid() {
		return zero, errors.New("invalid result-bound runtime close reply")
	}
	if (begin && reply.Phase == "idle") || *reply.Maintenance.Record != record || reply.Maintenance.Control.Committed != record.After() {
		return zero, ErrProcessPin
	}
	return reply, nil
}
