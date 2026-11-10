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

const quiescencePath = maintenancePath + "/quiesce"

// QuiesceMaintenance is available ONLY on an incarnation-pinned client. The
// complete original record, not just owner/idle counts, must match the reply.
// Each retry performs the same freeze and new live observation; no cached
// certificate or ordinary/unpinned fallback is accepted.
func (c *PinnedClient) QuiesceMaintenance(ctx context.Context, record MaintenanceRecord) (MaintenanceWorkReply, error) {
	var zero MaintenanceWorkReply
	if c == nil || c.client == nil || c.client.live == nil {
		return zero, ErrProcessPin
	}
	if !record.Valid() {
		return zero, ErrInvalid
	}
	if e := c.client.live(); e != nil {
		return zero, e
	}
	data, _ := json.Marshal(record.Request)
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://node.local"+quiescencePath, bytes.NewReader(data))
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
		return zero, errors.New("quiescence reply too large")
	}
	if e = c.client.live(); e != nil {
		return zero, e
	}
	if response.StatusCode != 200 {
		if response.StatusCode == 404 || response.StatusCode == 501 {
			return zero, ErrMaintenanceUnsupported
		}
		var failure controlError
		if strictjson.Decode(b, &failure) != nil {
			return zero, errors.New("invalid quiescence failure")
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
			return zero, errors.New("quiescence request refused")
		}
	}
	var reply MaintenanceWorkReply
	if strictjson.Decode(b, &reply) != nil || !reply.valid() {
		return zero, errors.New("invalid quiescence reply")
	}
	if *reply.Maintenance.Record != record || reply.Maintenance.Control.Committed != record.After() {
		return zero, ErrProcessPin
	}
	return reply, nil
}
