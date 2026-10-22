package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/123123213weqw/Xandbox/internal/hostclock"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type Options struct {
	MaxSessions, MaxTenantSessions, MaxAttempts int
	RetryInterval                               time.Duration
}
type route struct {
	Revision uint64
	Ref      sandbox.Ref
	Permit   *sandbox.Admission
}
type attempt struct {
	key, spec         string
	done              chan struct{}
	index             int
	phaseMu           sync.Mutex // Only bounded memory operations, never I/O.
	ref               sandbox.Ref
	fenced, cancelled bool
	startedNS         int64
}
type entry struct {
	tenant      string     // Immutable; record snapshots are replaced under mu.
	mu          sync.Mutex // Never held for Store/Core lifecycle I/O.
	record      Record
	attempts    map[string]*attempt
	refs        map[sandbox.Ref]bool
	busy, dirty bool
	closed      atomic.Bool
	route       atomic.Pointer[route]
}
type Broker struct {
	mu              sync.Mutex
	core            *sandbox.Manager
	store           Store
	opts            Options
	records         map[string]*entry
	keys            map[string]*entry
	tenantCounts    map[string]int
	closing         bool
	closingCh       chan struct{}
	closeOnce       sync.Once
	fencesInstalled atomic.Bool
	lifeCtx         context.Context
	cancelLife      context.CancelFunc
	ops             atomic.Int64
	wake            chan struct{}
	done            chan struct{}
}

func New(core *sandbox.Manager, store Store, opts Options) (*Broker, error) {
	if core == nil || store == nil {
		return nil, errors.New("session core and store required")
	}
	if opts.MaxSessions == 0 {
		opts.MaxSessions = 1000
	}
	if opts.MaxTenantSessions == 0 {
		opts.MaxTenantSessions = min(100, opts.MaxSessions)
	}
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = MaxHistory
	}
	if opts.RetryInterval == 0 {
		opts.RetryInterval = 100 * time.Millisecond
	}
	if opts.MaxSessions < 1 || opts.MaxSessions > MaxRecords || opts.MaxTenantSessions < 1 || opts.MaxTenantSessions > opts.MaxSessions || opts.MaxAttempts < 1 || opts.MaxAttempts > MaxHistory || opts.RetryInterval < time.Millisecond {
		return nil, errors.New("invalid session bounds")
	}
	rows, err := store.Load()
	if err != nil {
		return nil, err
	}
	if len(rows) > MaxRecords {
		return nil, errors.New("session hard capacity exceeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{core: core, store: store, opts: opts, records: map[string]*entry{}, keys: map[string]*entry{}, tenantCounts: map[string]int{}, closingCh: make(chan struct{}), lifeCtx: ctx, cancelLife: cancel, wake: make(chan struct{}, 1), done: make(chan struct{})}
	// Validate the entire set and immutable Core ownership before touching any
	// session journal. Core's own restart policy fences ALL previous VM records.
	for _, r := range rows {
		if err := validate(r); err != nil {
			cancel()
			return nil, err
		}
		k := r.TenantID + "\x00" + r.CreateKeyHash
		if b.records[r.ID] != nil || b.keys[k] != nil {
			cancel()
			return nil, errors.New("duplicate session identity/key")
		}
		if !zeroRef(r.Current) && !core.OwnsScoped(r.TenantID, r.Current) {
			cancel()
			return nil, errors.New("session current has no core authority")
		}
		for _, a := range r.Attempts {
			if !zeroRef(a.From) && !core.OwnsScoped(r.TenantID, a.From) {
				cancel()
				return nil, errors.New("session previous has no core authority")
			}
			if !zeroRef(a.Target) && a.State != "FAILED" && !core.OwnsScoped(r.TenantID, a.Target) {
				cancel()
				return nil, errors.New("session target has no core authority")
			}
		}
		e := newEntry(r)
		e.closed.Store(true)
		b.records[r.ID], b.keys[k] = e, e
		b.tenantCounts[r.TenantID]++
	}
	for _, e := range b.records {
		r := clone(e.record)
		r.State = Closed
		r.UpdatedAt = time.Now().UTC()
		for n := range r.Attempts {
			if r.Attempts[n].State == Preparing || r.Attempts[n].State == Prepared {
				r.Attempts[n].State = "FAILED"
			}
		}
		// No generation or route is revived even if the last binding write committed.
		if err := store.Save(r); err != nil {
			cancel()
			return nil, fmt.Errorf("persist session recovery fence: %w", err)
		}
		e.record = r
		b.revokeAll(e)
	}
	go b.journal()
	return b, nil
}
func newEntry(r Record) *entry {
	e := &entry{tenant: r.TenantID, record: clone(r), attempts: map[string]*attempt{}, refs: map[sandbox.Ref]bool{}}
	if !zeroRef(r.Current) {
		e.refs[r.Current] = true
	}
	for n, a := range r.Attempts {
		done := make(chan struct{})
		close(done)
		e.attempts[a.KeyHash] = &attempt{key: a.KeyHash, spec: a.SpecHash, index: n, done: done}
		if !zeroRef(a.From) {
			e.refs[a.From] = true
		}
		if !zeroRef(a.Target) {
			e.refs[a.Target] = true
		}
	}
	return e
}
func requestHashes(kind, key string, expected uint64, req sandbox.CreateRequest) (string, string, error) {
	if len(key) < 1 || len(key) > 128 {
		return "", "", sandbox.ErrInvalid
	}
	for _, v := range []byte(key) {
		if v < 33 || v > 126 {
			return "", "", sandbox.ErrInvalid
		}
	}
	kh := sha256.Sum256([]byte(kind + "\x00" + key))
	data, err := json.Marshal(struct {
		Kind     string
		Expected uint64
		Create   sandbox.CreateRequest
	}{kind, expected, req})
	if err != nil {
		return "", "", err
	}
	sh := sha256.Sum256(data)
	return hex.EncodeToString(kh[:]), hex.EncodeToString(sh[:]), nil
}
func randomID() (string, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	return hex.EncodeToString(id[:]), err
}
func (b *Broker) begin() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing {
		return sandbox.ErrClosing
	}
	b.ops.Add(1)
	return nil
}
func (b *Broker) notify() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}
func (b *Broker) lookup(tenant, id string) (*entry, error) {
	b.mu.Lock()
	e := b.records[id]
	b.mu.Unlock()
	if e == nil || tenant == "" || e.tenant != tenant {
		return nil, sandbox.ErrNotFound
	}
	return e, nil
}

func (b *Broker) Open(ctx context.Context, owner sandbox.Owner, key string, req sandbox.CreateRequest) (Result, error) {
	if !owner.Valid() {
		return Result{}, sandbox.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := b.begin(); err != nil {
		return Result{}, err
	}
	defer b.ops.Add(-1)
	req, err := sandbox.NormalizeCreate(req)
	if err != nil {
		return Result{}, err
	}
	kh, sh, err := requestHashes("create", key, 0, req)
	if err != nil {
		return Result{}, err
	}
	start, err := hostclock.NowNS()
	if err != nil {
		return Result{}, err
	}
	id, err := randomID()
	if err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return Result{}, sandbox.ErrClosing
	}
	if e := b.keys[owner.TenantID+"\x00"+kh]; e != nil {
		b.mu.Unlock()
		return b.replay(ctx, e, kh, sh)
	}
	if len(b.records) >= b.opts.MaxSessions {
		b.mu.Unlock()
		return Result{}, ErrCapacity
	}
	if b.tenantCounts[owner.TenantID] >= b.opts.MaxTenantSessions {
		b.mu.Unlock()
		return Result{}, ErrTenantCapacity
	}
	if b.records[id] != nil {
		b.mu.Unlock()
		return Result{}, errors.New("random session identity collision")
	}
	r := Record{ID: id, TenantID: owner.TenantID, CreateKeyHash: kh, CreateSpecHash: sh, State: Creating, CreatedAt: now, UpdatedAt: now, Attempts: []Attempt{{KeyHash: kh, SpecHash: sh, State: Preparing, ExpectedRevision: 0, ResultRevision: 1, StartedAt: now}}}
	e := newEntry(r)
	a := &attempt{key: kh, spec: sh, index: 0, done: make(chan struct{}), startedNS: start}
	e.attempts[kh] = a
	e.busy = true
	b.records[id], b.keys[owner.TenantID+"\x00"+kh] = e, e
	b.tenantCounts[owner.TenantID]++
	b.mu.Unlock()
	defer b.finish(e, a)
	return b.mutate(ctx, owner, e, a, req)
}

func (b *Broker) Switch(ctx context.Context, owner sandbox.Owner, id, key string, req SwitchRequest) (Result, error) {
	if !owner.Valid() {
		return Result{}, sandbox.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := b.begin(); err != nil {
		return Result{}, err
	}
	defer b.ops.Add(-1)
	e, err := b.lookup(owner.TenantID, id)
	if err != nil {
		return Result{}, err
	}
	if req.ExpectedRevision == 0 {
		return Result{}, sandbox.ErrInvalid
	}
	req.Create, err = sandbox.NormalizeCreate(req.Create)
	if err != nil {
		return Result{}, err
	}
	kh, sh, err := requestHashes("switch", key, req.ExpectedRevision, req.Create)
	if err != nil {
		return Result{}, err
	}
	start, err := hostclock.NowNS()
	if err != nil {
		return Result{}, err
	}
	e.mu.Lock()
	if _, exists := e.attempts[kh]; exists {
		e.mu.Unlock()
		return b.replay(ctx, e, kh, sh)
	}
	if e.closed.Load() {
		e.mu.Unlock()
		return Result{}, ErrGone
	}
	if e.busy {
		e.mu.Unlock()
		return Result{}, ErrBusy
	}
	if e.record.Revision != req.ExpectedRevision {
		e.mu.Unlock()
		return Result{}, ErrStale
	}
	if len(e.record.Attempts) >= b.opts.MaxAttempts {
		e.mu.Unlock()
		return Result{}, ErrHistory
	}
	a := &attempt{key: kh, spec: sh, index: len(e.record.Attempts), done: make(chan struct{}), startedNS: start}
	e.record.Attempts = append(e.record.Attempts, Attempt{KeyHash: kh, SpecHash: sh, ExpectedRevision: req.ExpectedRevision, ResultRevision: req.ExpectedRevision + 1, From: e.record.Current, State: Preparing, StartedAt: time.Now().UTC()})
	e.record.State = Preparing
	e.record.UpdatedAt = time.Now().UTC()
	e.attempts[kh] = a
	e.busy = true
	e.mu.Unlock()
	defer b.finish(e, a)
	return b.mutate(ctx, owner, e, a, req.Create)
}

func (b *Broker) replay(ctx context.Context, e *entry, kh, sh string) (Result, error) {
	e.mu.Lock()
	a := e.attempts[kh]
	if a == nil || a.spec != sh {
		e.mu.Unlock()
		return Result{}, sandbox.ErrIdempotencyConflict
	}
	done := a.done
	e.mu.Unlock()
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case <-b.closingCh:
		return Result{}, sandbox.ErrClosing
	case <-done:
	}
	e.mu.Lock()
	r := clone(e.record)
	saved := r.Attempts[a.index]
	e.mu.Unlock()
	rt := e.route.Load()
	if e.closed.Load() || saved.State != "COMMITTED" || rt == nil || rt.Revision != saved.ResultRevision || rt.Ref != saved.Target || !b.core.UsableScoped(r.TenantID, rt.Ref) {
		return Result{}, ErrGone
	}
	return Result{ID: r.ID, Revision: rt.Revision, Current: rt.Ref, Previous: saved.From, Timings: saved.Timings}, nil
}

func (b *Broker) persist(e *entry, r Record) error {
	r.UpdatedAt = time.Now().UTC()
	e.mu.Lock()
	e.record = clone(r)
	if e.closed.Load() {
		e.record.State = Closed
	}
	e.mu.Unlock()
	err := b.store.Save(r)
	e.mu.Lock()
	if e.closed.Load() {
		e.record.State = Closed
		e.dirty = true
	}
	e.mu.Unlock()
	return err
}
func (b *Broker) copy(e *entry) Record { e.mu.Lock(); defer e.mu.Unlock(); return clone(e.record) }
func (b *Broker) finish(e *entry, a *attempt) {
	e.mu.Lock()
	e.busy = false
	close(a.done)
	e.mu.Unlock()
	b.notify()
}
func (b *Broker) refOf(a *attempt) sandbox.Ref {
	a.phaseMu.Lock()
	defer a.phaseMu.Unlock()
	return a.ref
}
func (b *Broker) cancelCandidate(e *entry, a *attempt) {
	a.phaseMu.Lock()
	if a.fenced && !e.closed.Load() {
		a.phaseMu.Unlock()
		return
	}
	a.cancelled = true
	ref := a.ref
	a.phaseMu.Unlock()
	if !zeroRef(ref) {
		_ = b.core.RevokeScoped(e.tenant, ref)
	}
}
func (b *Broker) capture(e *entry, a *attempt, ctx context.Context, ref sandbox.Ref) {
	a.phaseMu.Lock()
	a.ref = ref
	cancelled := a.cancelled || ctx.Err() != nil
	a.phaseMu.Unlock()
	e.mu.Lock()
	e.refs[ref] = true
	tenant := e.record.TenantID
	e.mu.Unlock()
	if cancelled || e.closed.Load() {
		_ = b.core.RevokeScoped(tenant, ref)
	}
}
func (b *Broker) closeEntry(e *entry) {
	e.closed.Store(true)
	e.route.Store(nil)
	e.mu.Lock()
	e.record.State = Closed
	e.record.UpdatedAt = time.Now().UTC()
	e.dirty = true
	e.mu.Unlock()
	b.revokeAll(e)
	b.notify()
}
func (b *Broker) revokeAll(e *entry) {
	e.mu.Lock()
	tenant := e.record.TenantID
	refs := make([]sandbox.Ref, 0, len(e.refs))
	for ref := range e.refs {
		refs = append(refs, ref)
	}
	e.mu.Unlock()
	for _, ref := range refs {
		_ = b.core.RevokeScoped(tenant, ref)
	}
}
func (b *Broker) failClosed(e *entry, a *attempt) error {
	ref := b.refOf(a)
	e.mu.Lock()
	e.record.Attempts[a.index].State = "FAILED"
	if !zeroRef(ref) {
		e.record.Attempts[a.index].Target = ref
	}
	e.mu.Unlock()
	b.closeEntry(e)
	return ErrUnavailable
}
func (b *Broker) abort(e *entry, a *attempt, cause error) (Result, error) {
	ref := b.refOf(a)
	r := b.copy(e)
	if !zeroRef(ref) {
		_ = b.core.RevokeScoped(r.TenantID, ref)
	}
	if a.index == 0 || e.closed.Load() {
		return Result{}, b.failClosed(e, a)
	}
	r.Attempts[a.index].State = "FAILED"
	r.Attempts[a.index].Target = ref
	r.State = Active
	if err := b.persist(e, r); err != nil {
		return Result{}, b.failClosed(e, a)
	}
	if e.closed.Load() {
		return Result{}, ErrGone
	}
	return Result{}, cause
}
func millis(start, end int64) float64 {
	if start <= 0 || end < start {
		return 0
	}
	return float64(end-start) / 1e6
}

func (b *Broker) mutate(ctx context.Context, owner sandbox.Owner, e *entry, a *attempt, req sandbox.CreateRequest) (Result, error) {
	r := b.copy(e)
	expected := r.Attempts[a.index].ExpectedRevision
	desired := expected + 1
	if err := b.persist(e, r); err != nil {
		return Result{}, b.failClosed(e, a)
	}
	if e.closed.Load() {
		return Result{}, b.failClosed(e, a)
	}
	if err := ctx.Err(); err != nil {
		return b.abort(e, a, err)
	}
	opCtx, cancel := context.WithCancel(b.lifeCtx)
	stopCaller := context.AfterFunc(ctx, cancel)
	cancelDone := make(chan struct{})
	stopCandidate := context.AfterFunc(opCtx, func() { defer close(cancelDone); b.cancelCandidate(e, a) })
	defer func() {
		stopCaller()
		if !stopCandidate() {
			<-cancelDone
		}
		cancel()
	}()
	permit := sandbox.NewAdmission(func(ref sandbox.Ref) bool {
		rt := e.route.Load()
		return !e.closed.Load() && rt != nil && rt.Revision == desired && rt.Ref == ref
	})
	// Managed keys are separately domain-hashed inside Core, so an ordinary
	// tenant create cannot preoccupy this candidate with a previously used VM.
	sum := sha256.Sum256([]byte(r.ID + "\x00" + a.key))
	vmKey := "session-" + hex.EncodeToString(sum[:])
	candidate, err := b.core.CreateManagedScoped(opCtx, owner, vmKey, req, permit, func(ref sandbox.Ref) { b.capture(e, a, opCtx, ref) })
	if err != nil {
		return b.abort(e, a, err)
	}
	readyNS, readyClockErr := hostclock.NowNS()
	if opCtx.Err() != nil {
		return b.abort(e, a, opCtx.Err())
	}
	if e.closed.Load() {
		return Result{}, b.failClosed(e, a)
	}
	r = b.copy(e)
	r.State = Prepared
	r.Attempts[a.index].State = Prepared
	r.Attempts[a.index].Target = candidate.Ref
	r.Attempts[a.index].ReadyAt = time.Now().UTC()
	if err := b.persist(e, r); err != nil {
		return Result{}, b.failClosed(e, a)
	}
	// This short phase lock linearizes pre-fence cancellation. After fencing,
	// caller cancellation cannot undo the transaction or revive the old route.
	if !b.core.UsableScoped(owner.TenantID, candidate.Ref) {
		return b.abort(e, a, ErrGone)
	}
	a.phaseMu.Lock()
	if a.cancelled || opCtx.Err() != nil || e.closed.Load() {
		a.phaseMu.Unlock()
		return b.abort(e, a, context.Canceled)
	}
	a.fenced = true
	a.phaseMu.Unlock()
	fencedNS, fenceClockErr := hostclock.NowNS()
	e.route.Store(nil)
	old := r.Current
	if !zeroRef(old) {
		if err := b.core.RevokeScoped(owner.TenantID, old); err != nil {
			return Result{}, b.failClosed(e, a)
		}
	}
	r = b.copy(e)
	r.State = Active
	r.Current = candidate.Ref
	r.Revision = desired
	r.Attempts[a.index].State = "COMMITTED"
	r.Attempts[a.index].FencedAt = time.Now().UTC()
	r.Attempts[a.index].CommitStartedAt = time.Now().UTC()
	if err := b.persist(e, r); err != nil {
		return Result{}, b.failClosed(e, a)
	}
	commitNS, commitClockErr := hostclock.NowNS()
	if e.closed.Load() || !b.core.UsableScoped(owner.TenantID, candidate.Ref) {
		return Result{}, b.failClosed(e, a)
	}
	e.route.Store(&route{Revision: desired, Ref: candidate.Ref, Permit: permit})
	// A concurrent Close must win even if its nil publication raced this Store.
	if e.closed.Load() {
		e.route.Store(nil)
		_ = b.core.RevokeScoped(owner.TenantID, candidate.Ref)
		return Result{}, ErrGone
	}
	publishedNS, publishClockErr := hostclock.NowNS()
	timing := Timings{}
	if readyClockErr == nil && fenceClockErr == nil && commitClockErr == nil && publishClockErr == nil {
		timing = Timings{Measured: true, AdmissionRevokedMS: millis(a.startedNS, fencedNS), CandidateReadyMS: millis(a.startedNS, readyNS), FenceToCommitMS: millis(fencedNS, commitNS), TotalMS: millis(a.startedNS, publishedNS)}
	}
	// Process-local observations; later journal writes may retain them, but a
	// successful binding never depends on persisting its own post-fsync timing.
	e.mu.Lock()
	e.record.Attempts[a.index].Timings = timing
	e.mu.Unlock()
	return Result{ID: r.ID, Revision: desired, Current: candidate.Ref, Previous: old, Timings: timing}, nil
}

func (b *Broker) Exec(tenant, id string, revision uint64, req sandbox.ExecRequest) (sandbox.Job, error) {
	if revision == 0 {
		return sandbox.Job{}, sandbox.ErrInvalid
	}
	e, err := b.lookup(tenant, id)
	if err != nil {
		return sandbox.Job{}, err
	}
	rt := e.route.Load()
	if e.closed.Load() {
		return sandbox.Job{}, ErrGone
	}
	if rt == nil {
		return sandbox.Job{}, ErrBusy
	}
	if rt.Revision != revision {
		return sandbox.Job{}, ErrStale
	}
	// No lock is held while Core waits for its record. The capability rechecks
	// this exact version+Ref at Core's actual execution-admission point.
	req.Generation = rt.Ref.Generation
	return b.core.ExecManagedScoped(tenant, rt.Ref.ID, req, rt.Permit)
}
func (b *Broker) Get(tenant, id string) (Record, bool, error) {
	e, err := b.lookup(tenant, id)
	if err != nil {
		return Record{}, false, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r := clone(e.record)
	rt := e.route.Load()
	closed := e.closed.Load()
	if closed {
		r.State = Closed
		return r, false, nil
	}
	if rt != nil {
		r.Current = rt.Ref
		r.Revision = rt.Revision
		return r, true, nil
	}
	return r, false, nil
}

// CloseSession revokes routing immediately, without waiting for journal I/O.
// It is NOT a durable delete acknowledgement. Closed metadata/keys are retained.
func (b *Broker) CloseSession(tenant, id string, revision uint64) error {
	if err := b.begin(); err != nil {
		return err
	}
	defer b.ops.Add(-1)
	e, err := b.lookup(tenant, id)
	if err != nil {
		return err
	}
	if revision == 0 {
		return sandbox.ErrInvalid
	}
	e.mu.Lock()
	rt := e.route.Load()
	if e.closed.Load() {
		current := e.record.Revision
		e.mu.Unlock()
		if current != revision {
			return ErrStale
		}
		return nil
	}
	if rt == nil {
		e.mu.Unlock()
		return ErrBusy
	}
	if rt.Revision != revision {
		e.mu.Unlock()
		return ErrStale
	}
	e.closed.Store(true)
	e.route.Store(nil)
	e.record.State = Closed
	e.record.UpdatedAt = time.Now().UTC()
	e.dirty = true
	e.mu.Unlock()
	b.revokeAll(e)
	b.notify()
	return nil
}

func (b *Broker) all() []*entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*entry, 0, len(b.records))
	for _, e := range b.records {
		out = append(out, e)
	}
	return out
}
func (b *Broker) journal() {
	defer close(b.done)
	ticker := time.NewTicker(b.opts.RetryInterval)
	defer ticker.Stop()
	for {
		dirty := false
		for _, e := range b.all() {
			e.mu.Lock()
			if !e.dirty || e.busy {
				dirty = dirty || e.dirty
				e.mu.Unlock()
				continue
			}
			e.busy = true
			r := clone(e.record)
			r.State = Closed
			for n := range r.Attempts {
				if r.Attempts[n].State == Preparing || r.Attempts[n].State == Prepared {
					r.Attempts[n].State = "FAILED"
				}
			}
			e.mu.Unlock()
			err := b.store.Save(r)
			e.mu.Lock()
			if err == nil {
				e.record = r
				e.dirty = false
			} else {
				dirty = true
			}
			e.busy = false
			e.mu.Unlock()
		}
		if b.fencesInstalled.Load() && b.ops.Load() == 0 && !dirty && b.clean() {
			return
		}
		select {
		case <-ticker.C:
		case <-b.wake:
		}
	}
}
func (b *Broker) clean() bool {
	for _, e := range b.all() {
		e.mu.Lock()
		dirty := e.dirty || e.busy
		e.mu.Unlock()
		if dirty {
			return false
		}
	}
	return true
}

func (b *Broker) Close(ctx context.Context) error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closing = true
		close(b.closingCh)
		b.mu.Unlock()
		b.cancelLife()
		for _, e := range b.all() {
			b.closeEntry(e)
		}
		b.fencesInstalled.Store(true)
		b.notify()
	})
	select {
	case <-ctx.Done():
		return fmt.Errorf("session journal/mutations unfinished: %w", ctx.Err())
	case <-b.done:
		return nil
	}
}
func (b *Broker) Done() <-chan struct{} { return b.done }

// Uses identifies the exact authority behind an HTTP binding layer.
func (b *Broker) Uses(core *sandbox.Manager) bool { return b.core == core }
