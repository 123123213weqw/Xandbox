package sandbox

import (
	"context"
	"errors"
	"regexp"
	"time"
)

type State string

const (
	Creating   State = "CREATING"
	Ready      State = "READY"
	Stopping   State = "STOPPING"
	Stopped    State = "STOPPED"
	Reclaiming State = "RECLAIMING"
	Destroyed  State = "DESTROYED"
)

var (
	ErrNotFound                = errors.New("not found")
	ErrStale                   = errors.New("stale generation")
	ErrNotReady                = errors.New("sandbox is not ready")
	ErrClosing                 = errors.New("manager is closing")
	ErrCapacity                = errors.New("capacity exhausted; unreclaimed instances still count")
	ErrJobLimit                = errors.New("execution history limit reached; create a new sandbox")
	ErrInvalid                 = errors.New("invalid request")
	ErrTenantCapacity          = errors.New("tenant instance quota exhausted")
	ErrMetadataCapacity        = errors.New("ledger record capacity exhausted")
	ErrTenantMetadataCapacity  = errors.New("tenant ledger record capacity exhausted")
	ErrLedgerMigrationRequired = errors.New("legacy ledger requires offline migration")
	ErrIdempotencyConflict     = errors.New("idempotency key was used with a different request")
	ErrIdempotencyGone         = errors.New("idempotent creation is no longer usable; use a new key")
	// ErrBackendFenced requires admission fencing and recovery. It does NOT
	// certify stopped execution; Driver.Stop still has to prove that separately.
	ErrBackendFenced = errors.New("backend execution domain fenced; recovery required")
)

var tenantPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// Owner is authoritative controller policy, never a field supplied by a tenant.
type Owner struct {
	TenantID     string
	MaxInstances int
}

func (o Owner) Valid() bool {
	return tenantPattern.MatchString(o.TenantID) && o.MaxInstances >= 1 && o.MaxInstances <= 10_000
}

// Ref identifies one execution generation, not an authorization credential.
type Ref struct {
	ID         string `json:"id"`
	Generation string `json:"generation"`
}

type Limits struct {
	MaxExecMS      int `json:"max_exec_ms"`
	MaxOutputBytes int `json:"max_output_bytes"`
	MaxJobs        int `json:"max_jobs"`
}

type CreateRequest struct {
	TTLMS  int    `json:"ttl_ms"`
	Limits Limits `json:"limits"`
}

// Record is the durable lifecycle ledger. Execution results are not durable.
type Record struct {
	Ref
	Backend         string    `json:"backend"`
	TenantID        string    `json:"tenant_id"`
	CreateKeyHash   string    `json:"create_key_hash,omitempty"`
	CreateSpecHash  string    `json:"create_spec_hash,omitempty"`
	State           State     `json:"state"`
	DeleteRequested bool      `json:"delete_requested"`
	Limits          Limits    `json:"limits"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	StoppedAt       time.Time `json:"stopped_at,omitempty"`
	DestroyedAt     time.Time `json:"destroyed_at,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
}

type ExecRequest struct {
	Generation string   `json:"generation"`
	Argv       []string `json:"argv"`
	TimeoutMS  int      `json:"timeout_ms"`
}

type Output struct {
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated"`
}

type Job struct {
	ID string `json:"id"`
	Ref
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Output     Output    `json:"output"`
	Error      string    `json:"error,omitempty"`
}

// Preparation contains trusted runtime policy. DeadlineNS is in the host clock
// domain, captured before ownership persistence; ExpiresAt is only a wall-clock
// API projection. Recovery never resurrects a deadline from a previous boot.
type Preparation struct {
	Limits     Limits
	DeadlineNS int64
}

// Driver owns instance-specific resources. Stop must be idempotent and fence any
// execution outside Manager's tracked calls before reporting success. Cleanup
// must be idempotent and must never delete resources shared with another Ref.
// A mock driver is NOT an isolation boundary.
type Driver interface {
	Name() string
	Prepare(context.Context, Ref, Preparation) error
	// RefreshLease must be bounded/nonblocking; no disk or RPC waits. Failure
	// must fence the execution domain independently of reconciliation progress.
	RefreshLease(Ref) error
	// RevokeLease must also be bounded/nonblocking and free of disk/RPC I/O.
	// It may revoke only a live capability already owned by this exact Ref.
	// Reconciliation retries it independently of record/operation locks; it is
	// NOT proof of stopped execution, durability, cleanup or capacity release.
	RevokeLease(Ref) error
	Exec(context.Context, Ref, ExecRequest, int) (Output, error)
	Stop(context.Context, Ref) error
	Cleanup(context.Context, Ref) error
}

// Store.Save must atomically replace the previous ledger entry. Implementations
// may report a durability error after the replacement has already happened.
// Saves for distinct records may run concurrently. Manager serializes saves
// for one record; Load is used before concurrent lifecycle work starts.
type Store interface {
	Load() ([]Record, error)
	Save(Record) error
}

type Stats struct {
	Records              int    `json:"records"`
	RecordCapacity       int    `json:"record_capacity"`
	TenantRecordCapacity int    `json:"tenant_record_capacity"`
	Backend              string `json:"backend"`
	Active               int    `json:"active"`
	Capacity             int    `json:"capacity"`
	Recovering           int    `json:"recovering"`
	StopQueued           int    `json:"stop_queued"`
	CleanupQueued        int    `json:"cleanup_queued"`
	StopRunning          int    `json:"stop_running"`
	CleanupRunning       int    `json:"cleanup_running"`
	StopWorkers          int    `json:"stop_workers"`
	CleanupWorkers       int    `json:"cleanup_workers"`
	QueueCapacity        int    `json:"queue_capacity_per_pool"`
}
