package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type API struct {
	manager *sandbox.Manager
	auth    *access.Authenticator
}

type Options struct {
	Authenticator            *access.Authenticator
	AllowUnauthenticatedMock bool
}

type identityKey struct{}

// New is a local mock-test convenience; daemon startup uses NewConfigured.
func New(manager *sandbox.Manager) http.Handler {
	handler, err := NewConfigured(manager, Options{AllowUnauthenticatedMock: true})
	if err != nil {
		panic(err)
	}
	return handler
}

func NewConfigured(manager *sandbox.Manager, opts Options) (http.Handler, error) {
	if manager == nil {
		return nil, errors.New("manager is required")
	}
	if opts.Authenticator == nil && (!opts.AllowUnauthenticatedMock || manager.Stats().Backend != "mock") {
		return nil, errors.New("authentication required; unauthenticated access is mock-only and opt-in")
	}
	if opts.Authenticator != nil && opts.AllowUnauthenticatedMock {
		return nil, errors.New("conflicting authentication modes")
	}
	a := &API{manager: manager, auth: opts.Authenticator}
	node := manager.Stats()
	localOwner := sandbox.Owner{TenantID: "local", MaxInstances: node.Capacity}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		health := map[string]any{
			"backend": node.Backend, "isolation": false,
			"authentication":   a.auth != nil,
			"production_ready": false,
			"message":          "lifecycle prototype; production acceptance incomplete",
		}
		if node.Backend == "firecracker" {
			health["isolation"] = true // Configured mechanism, not a production certification.
			health["isolation_mechanism"] = "firecracker-kvm-jailer"
		}
		if a.auth == nil {
			health["stats"] = manager.Stats()
		}
		respond(w, http.StatusOK, health)
	})
	mux.HandleFunc("POST /v1/sandboxes", a.create)
	mux.HandleFunc("GET /v1/sandboxes/{id}", a.get)
	mux.HandleFunc("POST /v1/sandboxes/{id}/exec", a.exec)
	mux.HandleFunc("GET /v1/sandboxes/{id}/executions/{job}", a.job)
	mux.HandleFunc("POST /v1/sandboxes/{id}/stop", a.stop)
	mux.HandleFunc("DELETE /v1/sandboxes/{id}", a.destroy)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			mux.ServeHTTP(w, r)
			return
		}
		owner := localOwner
		if a.auth != nil {
			var err error
			headers := r.Header.Values("Authorization")
			if len(headers) == 1 {
				owner, err = a.auth.Authenticate(headers[0])
			} else {
				err = access.ErrUnauthorized
			}
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="xandbox"`)
				respond(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "UNAUTHORIZED", "message": "authentication required"}})
				return
			}
		}
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, owner)))
	}), nil
}

func identity(r *http.Request) sandbox.Owner { return r.Context().Value(identityKey{}).(sandbox.Owner) }

// Deliberately enumerate public fields; durable ledger details are not an API.
type recordView struct {
	sandbox.Ref
	Backend         string         `json:"backend"`
	TenantID        string         `json:"tenant_id"`
	State           sandbox.State  `json:"state"`
	DeleteRequested bool           `json:"delete_requested"`
	Limits          sandbox.Limits `json:"limits"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	ExpiresAt       time.Time      `json:"expires_at"`
	StoppedAt       time.Time      `json:"stopped_at,omitempty"`
	DestroyedAt     time.Time      `json:"destroyed_at,omitempty"`
	LastError       string         `json:"last_error,omitempty"`
}

func publicRecord(r sandbox.Record) recordView {
	v := recordView{Ref: r.Ref, Backend: r.Backend, TenantID: r.TenantID, State: r.State, DeleteRequested: r.DeleteRequested,
		Limits: r.Limits, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, ExpiresAt: r.ExpiresAt, StoppedAt: r.StoppedAt, DestroyedAt: r.DestroyedAt}
	if r.LastError != "" {
		v.LastError = "lifecycle operation pending or failed"
	}
	return v
}

func publicJob(j sandbox.Job) sandbox.Job {
	if j.Error != "" {
		switch j.Status {
		case "CANCELLED":
			j.Error = "execution cancelled"
		case "TIMED_OUT":
			j.Error = "execution deadline exceeded"
		default:
			j.Error = "execution failed"
		}
	}
	return j
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	var req sandbox.CreateRequest
	if !decode(w, r, &req) {
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	key := r.Header.Get("Idempotency-Key")
	if len(keys) > 1 || (a.auth != nil && key == "") {
		failure(w, sandbox.ErrInvalid)
		return
	}
	record, err := a.manager.CreateScoped(r.Context(), identity(r), key, req)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusCreated, publicRecord(record))
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	record, err := a.manager.GetScoped(identity(r).TenantID, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, publicRecord(record))
}

func (a *API) exec(w http.ResponseWriter, r *http.Request) {
	var req sandbox.ExecRequest
	if !decode(w, r, &req) {
		return
	}
	job, err := a.manager.ExecScoped(identity(r).TenantID, r.PathValue("id"), req)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusAccepted, publicJob(job))
}

func (a *API) job(w http.ResponseWriter, r *http.Request) {
	job, err := a.manager.GetJobScoped(identity(r).TenantID, r.PathValue("id"), r.PathValue("job"))
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, publicJob(job))
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
	record, err := a.manager.StopScoped(r.Context(), identity(r).TenantID, ref)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, publicRecord(record))
}

func (a *API) destroy(w http.ResponseWriter, r *http.Request) {
	ref, ok := refFrom(w, r)
	if !ok {
		return
	}
	record, err := a.manager.DestroyScoped(identity(r).TenantID, ref)
	if err != nil {
		failure(w, err)
		return
	}
	// 202 means deletion was accepted, not that the instance is already stopped.
	respond(w, http.StatusAccepted, publicRecord(record))
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 65_536)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		badJSON(w, err)
		return false
	}
	if err := strictjson.Decode(data, target); err != nil {
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
	respond(w, status, map[string]any{"error": map[string]string{"code": "INVALID_JSON", "message": "invalid JSON object"}})
}

func failure(w http.ResponseWriter, err error) {
	status, code, message := http.StatusInternalServerError, "INTERNAL", "internal operation failed"
	switch {
	case errors.Is(err, sandbox.ErrNotFound):
		status, code, message = 404, "NOT_FOUND", "not found"
	case errors.Is(err, sandbox.ErrInvalid):
		status, code, message = 400, "INVALID_REQUEST", "invalid request"
	case errors.Is(err, sandbox.ErrStale):
		status, code, message = 409, "STALE_GENERATION", "stale generation"
	case errors.Is(err, sandbox.ErrNotReady):
		status, code, message = 409, "NOT_READY", "sandbox is not ready"
	case errors.Is(err, sandbox.ErrIdempotencyConflict):
		status, code, message = 409, "IDEMPOTENCY_CONFLICT", "key already used with a different request"
	case errors.Is(err, sandbox.ErrIdempotencyGone):
		status, code, message = 410, "IDEMPOTENCY_GONE", "creation no longer usable; use a new key"
	case errors.Is(err, sandbox.ErrJobLimit):
		status, code, message = 429, "JOB_LIMIT", "execution history limit reached"
	case errors.Is(err, sandbox.ErrTenantCapacity):
		status, code, message = 429, "TENANT_QUOTA", "tenant instance quota exhausted"
	case errors.Is(err, sandbox.ErrCapacity), errors.Is(err, sandbox.ErrClosing):
		status, code, message = 503, "UNAVAILABLE", "service unavailable"
	}
	respond(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
