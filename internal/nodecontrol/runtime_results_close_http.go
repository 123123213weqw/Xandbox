package nodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// The outer private operator handler retains peer UID/ancestry/query/origin/
// authorization/header checks. This adds no TCP or tenant-token endpoint.
func serveRuntimeResultsClose(c *Controller, w http.ResponseWriter, r *http.Request) {
	fail := func(status int, code string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(controlError{code})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(405, "METHOD_NOT_ALLOWED")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		fail(415, "JSON_REQUIRED")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxCommandBytes))
	if e != nil {
		fail(413, "COMMAND_TOO_LARGE")
		return
	}
	var req RuntimeResultsCloseRequest
	if strictjson.Decode(raw, &req) != nil || !req.Valid() {
		fail(400, "INVALID_COMMAND")
		return
	}
	reply, e := c.RuntimeResultsClose(r.Context(), req)
	if e != nil {
		switch {
		case errors.Is(e, ErrRuntimeCloseUnsupported):
			fail(501, "RUNTIME_RESULTS_CLOSE_UNSUPPORTED")
		case errors.Is(e, ErrMaintenance):
			fail(409, "MAINTENANCE")
		case errors.Is(e, ErrBusy):
			fail(409, "BUSY")
		case errors.Is(e, ErrFenced):
			fail(503, "PERSISTENCE_FENCED")
		case errors.Is(e, ErrClosed):
			fail(503, "CLOSED")
		case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
			fail(408, "CANCELLED_BEFORE_ACCEPTANCE")
		default:
			fail(500, "INTERNAL")
		}
		return
	}
	_ = json.NewEncoder(w).Encode(reply)
}
