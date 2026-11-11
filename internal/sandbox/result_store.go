package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

var (
	ErrResultCapacity    = errors.New("retained result capacity exhausted")
	ErrResultUnavailable = errors.New("result retention unavailable")
)

const MaxResultBytes int64 = 1 << 30
const MaxResultRecords = 100_000

// ResultLimits are pessimistic logical reservations, not a filesystem quota or
// a syscall deadline. Nothing expires, evicts or acknowledges a tenant result.
type ResultLimits struct {
	Bytes, TenantBytes int64
	Records            int
}

func (l ResultLimits) valid() bool {
	return l.Bytes > 0 && l.Bytes <= MaxResultBytes && l.TenantBytes > 0 && l.TenantBytes <= l.Bytes && l.Records > 0 && l.Records <= MaxResultRecords
}

type ResultReservation struct {
	JobID          string    `json:"job_id"`
	Ref            Ref       `json:"ref"`
	TenantID       string    `json:"tenant_id"`
	MaxOutputBytes int       `json:"max_output_bytes"`
	StartedAt      time.Time `json:"started_at"`
}

func (r ResultReservation) valid() bool {
	return tokenPattern.MatchString(r.JobID) && validRef(r.Ref) && tenantPattern.MatchString(r.TenantID) && r.MaxOutputBytes >= 1 && r.MaxOutputBytes <= 65_536 && resultTimeValid(r.StartedAt)
}
func (r ResultReservation) charge() int64 { return 2*int64(r.MaxOutputBytes) + 16_384 }

// ResultStore is bound to the same exclusive controller ownership as Store.
// Reserve must be durable BEFORE Exec. Complete must be durable BEFORE a
// terminal result/accepted-work success can be published. Failed/ambiguous
// writes retain their capacity and must never be reinterpreted as success.
// Implementations never execute/replay a command. Bind rejects orphan owners.
type ResultStore interface {
	Bind([]Record) (bool, error)
	Reserve(ResultReservation) error
	Complete(Job) error
	Get(Ref, string, string) (Job, error)
}

type retainedOutput struct {
	Status     string    `json:"status"`
	FinishedAt time.Time `json:"finished_at"`
	Stdout     []byte    `json:"stdout"`
	Stderr     []byte    `json:"stderr"`
	ExitCode   int       `json:"exit_code"`
	Truncated  bool      `json:"truncated"`
	Error      []byte    `json:"error"`
}

const resultVersion = 2

// V1 remains readable but is never silently upgraded or sealed as V2.
type resultEnvelope struct {
	Version     int               `json:"version"`
	Reservation ResultReservation `json:"reservation"`
	Result      *retainedOutput   `json:"result,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
}

func (r resultEnvelope) valid() bool {
	if (r.Version != 1 && r.Version != resultVersion) || !r.Reservation.valid() {
		return false
	}
	if r.Version == 1 {
		if r.SHA256 != "" {
			return false
		}
	} else if !hashPattern.MatchString(r.SHA256) || r.SHA256 != resultDigest(r) {
		return false
	}
	if r.Result == nil {
		return true
	}
	o := r.Result
	if !resultTimeValid(o.FinishedAt) || len(o.Stdout)+len(o.Stderr) > r.Reservation.MaxOutputBytes || len(o.Error) > MaxLedgerErrorBytes || o.ExitCode < -1 || o.ExitCode > 255 {
		return false
	}
	switch o.Status {
	case "EXITED", "TIMED_OUT", "CANCELLED", "FAILED":
		return true
	}
	return false
}
func resultTimeValid(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	_, e := t.MarshalJSON()
	return e == nil
}
func resultDigest(r resultEnvelope) string {
	// Same typed field order and canonical encoding as V1, with an explicit V2
	// domain/version. Never include the checksum in its own digest.
	body := struct {
		Version     int               `json:"version"`
		Reservation ResultReservation `json:"reservation"`
		Result      *retainedOutput   `json:"result,omitempty"`
	}{r.Version, r.Reservation, r.Result}
	b, e := json.Marshal(body)
	if e != nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte("xandbox-result-record-v2\n"))
	h.Write(b)
	h.Write([]byte{'\n'})
	return hex.EncodeToString(h.Sum(nil))
}
func resultBytes(r resultEnvelope) []byte {
	if r.Version == resultVersion {
		r.SHA256 = resultDigest(r)
	}
	b, e := json.Marshal(r)
	if e != nil {
		return nil
	}
	return append(b, '\n')
}
func decodeResult(raw []byte) (resultEnvelope, error) {
	var r resultEnvelope
	if len(raw) == 0 || len(raw) > 2*65_536+16_384 || strictjson.Decode(raw, &r) != nil || !r.valid() || int64(len(raw)) > r.Reservation.charge() || !bytes.Equal(raw, resultBytes(r)) {
		return resultEnvelope{}, ErrResultUnavailable
	}
	return r, nil
}
func (r resultEnvelope) job() Job {
	j := Job{ID: r.Reservation.JobID, Ref: r.Reservation.Ref, StartedAt: r.Reservation.StartedAt, Status: "INTERRUPTED", Output: Output{ExitCode: -1}, Error: "execution outcome unknown after restart"}
	if r.Result != nil {
		o := r.Result
		j.Status = o.Status
		j.FinishedAt = o.FinishedAt
		j.Output = Output{Stdout: string(o.Stdout), Stderr: string(o.Stderr), ExitCode: o.ExitCode, Truncated: o.Truncated}
		j.Error = string(o.Error)
		j.ResultRetained = true
		j.ResultIntegrity = "legacy_unverified_v1"
		if r.Version == resultVersion {
			j.ResultIntegrity = "checksum_v2"
		}
	}
	return j
}
