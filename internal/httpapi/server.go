package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type API struct{ manager *sandbox.Manager }

func New(manager *sandbox.Manager) http.Handler {
	a := &API{manager: manager}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, map[string]any{
			"backend": manager.Stats().Backend, "isolation": false,
			"message": "mock lifecycle prototype; no host commands or microVMs are executed",
			"stats":   manager.Stats(),
		})
	})
	mux.HandleFunc("POST /v1/sandboxes", a.create)
	mux.HandleFunc("GET /v1/sandboxes/{id}", a.get)
	mux.HandleFunc("POST /v1/sandboxes/{id}/exec", a.exec)
	mux.HandleFunc("GET /v1/sandboxes/{id}/executions/{job}", a.job)
	mux.HandleFunc("POST /v1/sandboxes/{id}/stop", a.stop)
	mux.HandleFunc("DELETE /v1/sandboxes/{id}", a.destroy)
	return mux
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	var req sandbox.CreateRequest
	if !decode(w, r, &req) {
		return
	}
	record, err := a.manager.Create(r.Context(), req)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusCreated, record)
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	record, err := a.manager.Get(r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, record)
}

func (a *API) exec(w http.ResponseWriter, r *http.Request) {
	var req sandbox.ExecRequest
	if !decode(w, r, &req) {
		return
	}
	job, err := a.manager.Exec(r.PathValue("id"), req)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusAccepted, job)
}

func (a *API) job(w http.ResponseWriter, r *http.Request) {
	job, err := a.manager.GetJob(r.PathValue("id"), r.PathValue("job"))
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, job)
}

func refFrom(w http.ResponseWriter, r *http.Request) (sandbox.Ref, bool) {
	var body struct {
		Generation string `json:"generation"`
	}
	if !decode(w, r, &body) {
		return sandbox.Ref{}, false
	}
	return sandbox.Ref{ID: r.PathValue("id"), Generation: body.Generation}, true
}

func (a *API) stop(w http.ResponseWriter, r *http.Request) {
	ref, ok := refFrom(w, r)
	if !ok {
		return
	}
	record, err := a.manager.Stop(r.Context(), ref)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, record)
}

func (a *API) destroy(w http.ResponseWriter, r *http.Request) {
	ref, ok := refFrom(w, r)
	if !ok {
		return
	}
	record, err := a.manager.Destroy(ref)
	if err != nil {
		failure(w, err)
		return
	}
	// 202 means deletion was accepted, not that the instance is already stopped.
	respond(w, http.StatusAccepted, record)
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 65_536)
	decoder := json.NewDecoder(r.Body)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		badJSON(w, err)
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("exactly one JSON object is required")
		}
		badJSON(w, err)
		return false
	}
	if data := bytes.TrimSpace(raw); len(data) == 0 || data[0] != '{' {
		badJSON(w, errors.New("request body must be a JSON object"))
		return false
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if err := typed.Decode(target); err != nil {
		badJSON(w, err)
		return false
	}
	return true
}

func badJSON(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	respond(w, status, map[string]any{"error": map[string]string{"code": "INVALID_JSON", "message": err.Error()}})
}

func failure(w http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "INTERNAL"
	switch {
	case errors.Is(err, sandbox.ErrNotFound):
		status, code = http.StatusNotFound, "NOT_FOUND"
	case errors.Is(err, sandbox.ErrInvalid):
		status, code = http.StatusBadRequest, "INVALID_REQUEST"
	case errors.Is(err, sandbox.ErrStale):
		status, code = http.StatusConflict, "STALE_GENERATION"
	case errors.Is(err, sandbox.ErrNotReady):
		status, code = http.StatusConflict, "NOT_READY"
	case errors.Is(err, sandbox.ErrJobLimit):
		status, code = http.StatusTooManyRequests, "JOB_LIMIT"
	case errors.Is(err, sandbox.ErrCapacity), errors.Is(err, sandbox.ErrClosing):
		status, code = http.StatusServiceUnavailable, "UNAVAILABLE"
	}
	respond(w, status, map[string]any{"error": map[string]string{"code": code, "message": err.Error()}})
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
