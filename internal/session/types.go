// Package session provides experimental crash-fenced, versioned VM bindings.
// It never reuses a dirty VM and never treats binding commit as a Stop/GC proof.
package session

import (
	"errors"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

var (
	ErrStale          = errors.New("stale session revision")
	ErrBusy           = errors.New("session mutation already in progress")
	ErrGone           = errors.New("session or idempotent attempt is no longer usable")
	ErrCapacity       = errors.New("session metadata capacity exhausted")
	ErrTenantCapacity = errors.New("tenant session metadata capacity exhausted")
	ErrHistory        = errors.New("session mutation history exhausted")
	ErrUnavailable    = errors.New("session fenced; recovery required")
)

const (
	Creating   = "CREATING"
	Active     = "ACTIVE"
	Preparing  = "PREPARING"
	Prepared   = "PREPARED"
	Closed     = "CLOSED"
	MaxHistory = 64 // Includes the initial create; never silently evict old keys.
	MaxRecords = 10_000
)

type SwitchRequest struct {
	ExpectedRevision uint64                `json:"expected_revision"`
	Create           sandbox.CreateRequest `json:"create"`
}

type Timings struct {
	AdmissionRevokedMS float64 `json:"admission_revoked_ms"`
	Measured           bool    `json:"measured"`
	CandidateReadyMS   float64 `json:"candidate_ready_ms"`
	FenceToCommitMS    float64 `json:"fence_to_commit_ms"`
	TotalMS            float64 `json:"total_ms"`
}

type Attempt struct {
	KeyHash          string      `json:"key_hash"`
	SpecHash         string      `json:"spec_hash"`
	ExpectedRevision uint64      `json:"expected_revision"`
	ResultRevision   uint64      `json:"result_revision"`
	From             sandbox.Ref `json:"from"`
	Target           sandbox.Ref `json:"target"`
	State            string      `json:"state"`
	StartedAt        time.Time   `json:"started_at"`
	ReadyAt          time.Time   `json:"ready_at"`
	FencedAt         time.Time   `json:"fenced_at"`
	CommitStartedAt  time.Time   `json:"commit_started_at"`
	Timings          Timings     `json:"timings"`
}

type Record struct {
	ID             string      `json:"id"`
	TenantID       string      `json:"tenant_id"`
	CreateKeyHash  string      `json:"create_key_hash"`
	CreateSpecHash string      `json:"create_spec_hash"`
	Revision       uint64      `json:"revision"`
	Current        sandbox.Ref `json:"current"`
	State          string      `json:"state"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	Attempts       []Attempt   `json:"attempts"`
}

type Store interface {
	Load() ([]Record, error)
	Save(Record) error // Atomic replacement + file/directory fsync; error can be ambiguous.
}

type Result struct {
	ID       string      `json:"id"`
	Revision uint64      `json:"revision"`
	Current  sandbox.Ref `json:"current"`
	Previous sandbox.Ref `json:"previous"`
	Timings  Timings     `json:"timings"`
}

func clone(r Record) Record { r.Attempts = append([]Attempt(nil), r.Attempts...); return r }
