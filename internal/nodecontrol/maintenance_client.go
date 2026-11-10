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

const maintenancePath = "/v1/node/maintenance"

// Only the incarnation-pinned client exposes maintenance begin/status. No
// resume, release, force, arbitrary transport/root or unpinned fallback exists.
func (c *PinnedClient) MaintenanceStatus(ctx context.Context) (MaintenanceReply, error) {
	if c == nil || c.client == nil {
		return MaintenanceReply{}, ErrProcessPin
	}
	return c.client.callMaintenance(ctx, nil)
}
func (c *PinnedClient) BeginMaintenance(ctx context.Context, before State, request MaintenanceRequest) (MaintenanceReply, error) {
	if c == nil || c.client == nil {
		return MaintenanceReply{}, ErrProcessPin
	}
	want := MaintenanceRecord{Version: 1, Request: request, Before: before}
	if !want.Valid() {
		return MaintenanceReply{}, ErrInvalid
	}
	r, e := c.client.callMaintenance(ctx, &request)
	if e != nil {
		return MaintenanceReply{}, e
	}
	if r.Record == nil || *r.Record != want || r.Control.Committed != want.After() || r.Control.Phase != "ready" || r.Control.DesiredMode != ModeDrained || r.Control.AdmissionOpen || r.Control.PendingRequestID != "" {
		return MaintenanceReply{}, ErrProcessPin
	}
	return r, nil
}
func (c *Client) callMaintenance(ctx context.Context, request *MaintenanceRequest) (MaintenanceReply, error) {
	var zero MaintenanceReply
	if c.live == nil {
		return zero, ErrProcessPin
	}
	if e := c.live(); e != nil {
		return zero, e
	}
	var data []byte
	method := http.MethodGet
	if request != nil {
		if !request.Valid() {
			return zero, ErrInvalid
		}
		data, _ = json.Marshal(request)
		method = http.MethodPost
	}
	r, e := http.NewRequestWithContext(ctx, method, "http://node.local"+maintenancePath, bytes.NewReader(data))
	if e != nil {
		return zero, e
	}
	if request != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, e := c.http.Do(r)
	if e != nil {
		return zero, e
	}
	defer response.Body.Close()
	b, e := io.ReadAll(io.LimitReader(response.Body, MaxReplyBytes+1))
	if e != nil {
		return zero, e
	}
	if len(b) > MaxReplyBytes {
		return zero, errors.New("maintenance reply too large")
	}
	if e = c.live(); e != nil {
		return zero, e
	}
	if response.StatusCode != 200 {
		if response.StatusCode == 404 {
			return zero, ErrMaintenanceUnsupported
		}
		var failure controlError
		if strictjson.Decode(b, &failure) != nil {
			return zero, errors.New("invalid maintenance failure")
		}
		switch failure.Code {
		case "MAINTENANCE_UNSUPPORTED":
			return zero, ErrMaintenanceUnsupported
		case "MAINTENANCE":
			return zero, ErrMaintenance
		case "BUSY":
			return zero, ErrBusy
		case "CONFLICT":
			return zero, ErrConflict
		case "PERSISTENCE_FENCED":
			return zero, ErrFenced
		case "CLOSED":
			return zero, ErrClosed
		default:
			return zero, errors.New("maintenance request refused")
		}
	}
	var reply MaintenanceReply
	if strictjson.Decode(b, &reply) != nil || !reply.valid() {
		return zero, errors.New("invalid maintenance reply")
	}
	return reply, nil
}
