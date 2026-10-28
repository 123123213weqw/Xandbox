// Package diagnostics provides closed, bounded, best-effort process diagnostics.
// Enqueue is not a durability acknowledgment and these records are not an audit
// log of every accepted tenant operation. No arbitrary string enters a record.
package diagnostics

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Kind uint8
type Reason uint8

const (
	Unknown Kind = iota
	ServiceMock
	ServiceKVM
	PrepareFailed
	CleanupUnfinished
	SessionUnfinished
	ControlUnfinished
	OperatorUnfinished
	ListenerFailed
	ProcessFailed
	ProcessStopped
	CollectorClosed
	kindCount
)
const (
	Other Reason = iota
	Deadline
	Cancelled
	Configuration
	StateLock
	AuthMode
	DiagnosticsUnavailable
	// Append only: persisted version1 enum values must never be renumbered.
	IOFailure
	QuotaExceeded
	NoSpace
	ReadOnly
	NodeAdmission
	NodePlacement
	IOBackingQueue
	IODelegation
	BackendBinding
	QuotaCapabilities
	QuotaFilesystem
	QuotaOwnership
	QuotaMount
	reasonCount
)
const ReasonAttribute = "xandbox_reason"
const QueueCapacity = 64
const RetainedRecords = 128
const FrameBytes = 128
const HeaderBytes = 128
const RingBytes = 2*HeaderBytes + (RetainedRecords+1)*FrameBytes

var ErrPending = errors.New("diagnostic writer unfinished")
var ErrWrite = errors.New("diagnostic write unavailable")
var kindNames = [...]string{"unknown", "service_mock", "service_kvm", "prepare_failed", "cleanup_unfinished", "session_unfinished", "control_unfinished", "operator_unfinished", "listener_failed", "process_failed", "process_stopped", "collector_closed"}
var reasonNames = [...]string{"other", "deadline", "cancelled", "configuration", "state_lock", "auth_mode", "diagnostics_unavailable", "io", "quota", "no_space", "read_only", "node_admission", "node_placement", "io_backing_queue", "io_delegation", "backend_binding", "quota_capabilities", "quota_filesystem", "quota_ownership", "quota_mount"}

type Event struct {
	Kind          Kind   `json:"kind"`
	Reason        Reason `json:"reason"`
	TimeNS        int64  `json:"time_ns"`
	DroppedBefore uint64 `json:"dropped_before"`
}
type Record struct {
	Sequence uint64 `json:"sequence"`
	Event    Event  `json:"event"`
}

func (e Event) valid() bool { return e.Kind < kindCount && e.Reason < reasonCount && e.TimeNS > 0 }
func (k Kind) String() string {
	if k >= kindCount {
		return "unknown"
	}
	return kindNames[k]
}
func (r Reason) String() string {
	if r >= reasonCount {
		return "other"
	}
	return reasonNames[r]
}
func (k Kind) MarshalText() ([]byte, error)   { return []byte(k.String()), nil }
func (r Reason) MarshalText() ([]byte, error) { return []byte(r.String()), nil }
func ReasonFor(err error) Reason {
	if errors.Is(err, context.DeadlineExceeded) {
		return Deadline
	}
	if errors.Is(err, context.Canceled) {
		return Cancelled
	}
	return SystemReason(err)
}

// Fault preserves errors.Is/As without ever rendering the underlying error.
type Fault struct {
	Reason Reason
	Cause  error
}

func (e *Fault) Error() string { return "diagnostic class: " + e.Reason.String() }
func (e *Fault) Unwrap() error { return e.Cause }
func FailureReason(err error) Reason {
	var f *Fault
	if errors.As(err, &f) {
		return f.Reason
	}
	return ReasonFor(err)
}

type Stats struct {
	Enqueued, Dropped, Written, WriteErrors uint64
	Queued, Capacity                        int
	PrepareIO, PrepareQuota, PrepareOther   uint64
}
type counters struct {
	enqueued, dropped, written, writeErrors atomic.Uint64
	prepareIO, prepareQuota, prepareOther   atomic.Uint64
}
type recordStore interface {
	append(Event) error
	close() error
}
type Logger struct {
	mu         sync.Mutex // Only enqueue/closing; never held across storage or callbacks.
	closing    bool
	queue      chan Event
	stop, done chan struct{}
	once       sync.Once
	stats      counters
	err        error // Published by close(done).
}

func newLogger(store recordStore) *Logger {
	l := &Logger{queue: make(chan Event, QueueCapacity), stop: make(chan struct{}), done: make(chan struct{})}
	go l.write(store)
	return l
}
func (l *Logger) Emit(kind Kind, reason Reason) bool {
	if l == nil {
		return false
	}
	if kind >= kindCount || reason >= reasonCount {
		l.stats.dropped.Add(1)
		return false
	}
	// Count a valid producer observation even if queue/writer/Close later loses
	// the record. These atoms are NOT durable events or accepted-operation ACKs.
	if kind == PrepareFailed {
		switch reason {
		case IOFailure:
			l.stats.prepareIO.Add(1)
		case QuotaExceeded:
			l.stats.prepareQuota.Add(1)
		default:
			l.stats.prepareOther.Add(1)
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		l.stats.dropped.Add(1)
		return false
	}
	select {
	case <-l.done:
		l.stats.dropped.Add(1)
		return false
	default:
	}
	e := Event{Kind: kind, Reason: reason, TimeNS: time.Now().UnixNano(), DroppedBefore: l.stats.dropped.Load()}
	select {
	case l.queue <- e:
		l.stats.enqueued.Add(1)
		return true
	default:
		l.stats.dropped.Add(1)
		return false
	}
}
func (l *Logger) Stats() Stats {
	if l == nil {
		return Stats{Capacity: QueueCapacity}
	}
	return Stats{Enqueued: l.stats.enqueued.Load(), Dropped: l.stats.dropped.Load(), Written: l.stats.written.Load(), WriteErrors: l.stats.writeErrors.Load(), Queued: len(l.queue), Capacity: QueueCapacity, PrepareIO: l.stats.prepareIO.Load(), PrepareQuota: l.stats.prepareQuota.Load(), PrepareOther: l.stats.prepareOther.Load()}
}
func (l *Logger) write(s recordStore) {
	defer close(l.done)
	// Reject producers before draining lost events, including a producer that
	// arrived while the final append/close was failing. No accepted event stays
	// silently stranded in the queue after the writer terminates.
	defer func() {
		l.mu.Lock()
		l.closing = true
		for {
			select {
			case <-l.queue:
				l.stats.dropped.Add(1)
			default:
				l.mu.Unlock()
				return
			}
		}
	}()
	defer func() {
		if e := s.close(); e != nil {
			l.stats.writeErrors.Add(1)
			l.err = ErrWrite
		}
	}()
	persist := func(e Event) bool {
		if err := s.append(e); err != nil {
			l.stats.writeErrors.Add(1)
			l.stats.dropped.Add(1)
			l.err = ErrWrite
			return false
		}
		l.stats.written.Add(1)
		return true
	}
	for {
		select {
		case e := <-l.queue:
			if !persist(e) {
				return
			}
		case <-l.stop:
			for {
				select {
				case e := <-l.queue:
					if !persist(e) {
						return
					}
				default:
					persist(Event{Kind: CollectorClosed, Reason: Other, TimeNS: time.Now().UnixNano(), DroppedBefore: l.stats.dropped.Load()})
					return
				}
			}
		}
	}
}

// Close never closes a descriptor underneath a blocked storage syscall. On
// timeout the writer retains its resources; caller must retain service state
// ownership if it may return while the process still has unfinished workers.
func (l *Logger) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.once.Do(func() { l.mu.Lock(); l.closing = true; l.mu.Unlock(); close(l.stop) })
	// Completed storage owns no unfinished worker. A canceled caller must not
	// turn its already-published result (including ErrWrite) into ErrPending.
	select {
	case <-l.done:
		return l.err
	default:
	}
	select {
	case <-l.done:
		return l.err
	case <-ctx.Done():
		// Completion and cancellation may become ready together while this
		// goroutine is descheduled. Check the actual completion WITHOUT waiting
		// or extending the caller's budget; genuinely blocked storage remains
		// pending and keeps its descriptors and exclusive state ownership.
		select {
		case <-l.done:
			return l.err
		default:
			return ErrPending
		}
	}
}

// Handler discards arbitrary attributes/groups/message text, including errors.
// Only a direct primitive enum attribute on the known PrepareFailed producer is
// accepted. No Error/Is/As/Unwrap/LogValue method or attribute resolution occurs;
// even the attribute scan is bounded. WithAttrs/WithGroup retain nothing.
type Handler struct{ Logger *Logger }

func (*Handler) Enabled(context.Context, slog.Level) bool { return true }
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	k := Unknown
	switch r.Message {
	case "MOCK BACKEND: lifecycle simulation only; no sandbox isolation or host shell":
		k = ServiceMock
	case "EXPERIMENTAL FIRECRACKER: production acceptance incomplete":
		k = ServiceKVM
	case "Firecracker preparation failed":
		k = PrepareFailed
	case "cleanup unfinished; restart with the same state directory to recover":
		k = CleanupUnfinished
	case "session mutations unfinished; retain state ownership until process exit":
		k = SessionUnfinished
	case "sandboxd failed":
		k = ProcessFailed
	}
	reason := Other
	if k == PrepareFailed && r.NumAttrs() <= 4 {
		seen := false
		invalid := false
		r.Attrs(func(a slog.Attr) bool {
			if a.Key != ReasonAttribute {
				return true
			}
			if seen || a.Value.Kind() != slog.KindInt64 {
				invalid = true
				return true
			}
			seen = true
			n := a.Value.Int64()
			if n < 0 || n >= int64(reasonCount) {
				invalid = true
			} else {
				reason = Reason(n)
			}
			return true
		})
		if invalid {
			reason = Other
		}
	}
	h.Logger.Emit(k, reason)
	return nil
}
func (h *Handler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *Handler) WithGroup(string) slog.Handler      { return h }

// Snapshot is an observed, bounded private view, not proof that every event or
// the currently visible header has received a durability acknowledgment.
type Snapshot struct {
	Version          int      `json:"version"`
	ObservedSequence uint64   `json:"observed_sequence"`
	RetainedCapacity int      `json:"retained_capacity"`
	Overwritten      uint64   `json:"overwritten"`
	Records          []Record `json:"records"`
}
