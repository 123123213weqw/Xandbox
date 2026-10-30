package httpapi

import (
	"net/http"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

func sessionKey(r *http.Request) (string, error) {
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || keys[0] == "" {
		return "", sandbox.ErrInvalid
	}
	return keys[0], nil
}
func (a *API) openSession(w http.ResponseWriter, r *http.Request) {
	var req sandbox.CreateRequest
	if !decode(w, r, &req) {
		return
	}
	key, e := sessionKey(r)
	if e != nil {
		failure(w, e)
		return
	}
	ctx := a.manager.WithCreationTrace(r.Context(), telemetry.CreationSessionOpen)
	defer telemetry.EndCreationTrace(ctx)
	result, e := a.sessions.Open(ctx, identity(r), key, req)
	creationTiming(w, ctx)
	if e != nil {
		failure(w, e)
		return
	}
	respond(w, http.StatusCreated, result)
}
func (a *API) switchSession(w http.ResponseWriter, r *http.Request) {
	var req session.SwitchRequest
	if !decode(w, r, &req) {
		return
	}
	key, e := sessionKey(r)
	if e != nil {
		failure(w, e)
		return
	}
	ctx := a.manager.WithCreationTrace(r.Context(), telemetry.CreationSessionSwitch)
	defer telemetry.EndCreationTrace(ctx)
	result, e := a.sessions.Switch(ctx, identity(r), r.PathValue("id"), key, req)
	creationTiming(w, ctx)
	if e != nil {
		failure(w, e)
		return
	}
	respond(w, http.StatusOK, result)
}

type retiredView struct {
	Revision uint64      `json:"revision"`
	Ref      sandbox.Ref `json:"ref"`
}
type sessionView struct {
	Discarded  []sandbox.Ref `json:"discarded_candidates"`
	ID         string        `json:"id"`
	TenantID   string        `json:"tenant_id"`
	Revision   uint64        `json:"revision"`
	Current    sandbox.Ref   `json:"current"`
	Phase      string        `json:"phase"`
	HasBinding bool          `json:"has_binding"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
	Retired    []retiredView `json:"retired"`
}

func (a *API) getSession(w http.ResponseWriter, r *http.Request) {
	saved, has, e := a.sessions.Get(identity(r).TenantID, r.PathValue("id"))
	if e != nil {
		failure(w, e)
		return
	}
	view := sessionView{ID: saved.ID, TenantID: saved.TenantID, Revision: saved.Revision, Current: saved.Current, Phase: saved.State, HasBinding: has, CreatedAt: saved.CreatedAt, UpdatedAt: saved.UpdatedAt, Retired: []retiredView{}, Discarded: []sandbox.Ref{}}
	if saved.State == session.Active && !has {
		view.Phase = "COMMITTING"
	}
	for _, attempt := range saved.Attempts {
		if attempt.State == "FAILED" && attempt.Target != (sandbox.Ref{}) {
			view.Discarded = append(view.Discarded, attempt.Target)
		}
		if (attempt.State == "COMMITTED" || !attempt.FencedAt.IsZero() || saved.State == session.Closed) && attempt.ExpectedRevision != 0 {
			view.Retired = append(view.Retired, retiredView{Revision: attempt.ExpectedRevision, Ref: attempt.From})
		}
	}
	respond(w, http.StatusOK, view)
}
func (a *API) execSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision  uint64   `json:"revision"`
		Argv      []string `json:"argv"`
		TimeoutMS int      `json:"timeout_ms"`
	}
	if !decode(w, r, &req) {
		return
	}
	job, e := a.sessions.Exec(identity(r).TenantID, r.PathValue("id"), req.Revision, sandbox.ExecRequest{Argv: req.Argv, TimeoutMS: req.TimeoutMS})
	if e != nil {
		failure(w, e)
		return
	}
	respond(w, http.StatusAccepted, map[string]any{"revision": req.Revision, "sandbox": job.Ref, "job": publicJob(job)})
}
func (a *API) revokeSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExpectedRevision uint64 `json:"expected_revision"`
	}
	if !decode(w, r, &req) {
		return
	}
	if e := a.sessions.CloseSession(identity(r).TenantID, r.PathValue("id"), req.ExpectedRevision); e != nil {
		failure(w, e)
		return
	}
	// Explicitly not the durable DELETE contract of the per-VM endpoint.
	respond(w, http.StatusOK, map[string]any{"admission_revoked": true, "durable": false, "stop_confirmed": false, "reclamation_confirmed": false})
}
