package sandbox

import (
	"context"
	"errors"
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
	ErrNotFound = errors.New("not found")
	ErrStale    = errors.New("stale generation")
	ErrNotReady = errors.New("sandbox is not ready")
	ErrClosing  = errors.New("manager is closing")
	ErrCapacity = errors.New("capacity exhausted; unreclaimed instances still count")
	ErrJobLimit = errors.New("execution history limit reached; create a new sandbox")
	ErrInvalid  = errors.New("invalid request")
)

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

// Driver owns instance-specific resources. Stop must be idempotent and fence any
// execution outside Manager's tracked calls before reporting success. Cleanup
// must be idempotent and must never delete resources shared with another Ref.
// A mock driver is NOT an isolation boundary.
type Driver interface {
	Name() string
	Prepare(context.Context, Ref, Limits) error
	Exec(context.Context, Ref, ExecRequest, int) (Output, error)
	Stop(context.Context, Ref) error
	Cleanup(context.Context, Ref) error
}

// Store.Save must atomically replace the previous ledger entry. Implementations
// may report a durability error after the replacement has already happened.
type Store interface {
	Load() ([]Record, error)
	Save(Record) error
}

type Stats struct {
	Backend    string `json:"backend"`
	Active     int    `json:"active"`
	Capacity   int    `json:"capacity"`
	Recovering int    `json:"recovering"`
}
