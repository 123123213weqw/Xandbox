package sandbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

type Options struct {
	MaxInstances     int
	OperationTimeout time.Duration
	ReapInterval     time.Duration
	RetryDelay       time.Duration
}

type execution struct {
	job    Job
	cancel context.CancelFunc
}

type instance struct {
	opMu     sync.Mutex // Serializes preparation, stop, and cleanup, not execution.
	mu       sync.Mutex
	record   Record
	tenantID string // Immutable after registration; safe under Manager.mu.
	prepared chan struct{}
	jobs     map[string]*execution
	running  int
	idle     chan struct{}
	retryAt  time.Time
}

type Manager struct {
	mu         sync.Mutex
	records    map[string]*instance
	createKeys map[string]*instance
	active     map[string]*instance // Capacity is returned only after durable cleanup.
	closing    bool
	driver     Driver
	store      Store
	opts       Options
	ctx        context.Context
	cancel     context.CancelFunc
	wake       chan struct{}
	workerDone chan struct{}
}

func NewManager(store Store, driver Driver, opts Options) (*Manager, error) {
	if opts.MaxInstances <= 0 {
		opts.MaxInstances = 32
	}
	if opts.MaxInstances > 10_000 {
		return nil, fmt.Errorf("maximum instances exceeds 10000")
	}
	if opts.OperationTimeout <= 0 {
		opts.OperationTimeout = 2 * time.Second
	}
	if opts.ReapInterval <= 0 {
		opts.ReapInterval = 100 * time.Millisecond
	}
	if opts.RetryDelay <= 0 {
		opts.RetryDelay = 500 * time.Millisecond
	}
	records, err := store.Load()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		records: make(map[string]*instance), active: make(map[string]*instance),
		createKeys: make(map[string]*instance),
		driver:     driver, store: store, opts: opts, ctx: ctx, cancel: cancel,
		wake: make(chan struct{}, 1), workerDone: make(chan struct{}),
	}
	for _, r := range records {
		if _, exists := m.records[r.ID]; exists {
			cancel()
			return nil, fmt.Errorf("duplicate ledger identity %s", r.ID)
		}
		// Legacy v0 records were owned only by the local controller.
		if r.TenantID == "" {
			r.TenantID = "local"
		}
		if !tenantPattern.MatchString(r.TenantID) ||
			(r.CreateKeyHash == "") != (r.CreateSpecHash == "") ||
			(r.CreateKeyHash != "" && (!hashPattern.MatchString(r.CreateKeyHash) || !hashPattern.MatchString(r.CreateSpecHash))) {
			cancel()
			return nil, errors.New("invalid ledger ownership or idempotency metadata")
		}
		i := newInstance(r)
		if r.CreateKeyHash != "" {
			key := r.TenantID + "\x00" + r.CreateKeyHash
			if m.createKeys[key] != nil {
				cancel()
				return nil, errors.New("duplicate ledger idempotency key")
			}
			m.createKeys[key] = i
		}
		m.records[r.ID] = i
		if r.State == Destroyed {
			continue
		}
		if r.Backend != driver.Name() {
			cancel()
			return nil, fmt.Errorf("cannot recover backend %q with %q", r.Backend, driver.Name())
		}
		// v0 never resurrects a previous generation after a controller restart.
		r.DeleteRequested = true
		r.State = Stopping
		r.LastError = "controller restart: previous generation fenced for recovery"
		r.UpdatedAt = time.Now().UTC()
		if err := store.Save(r); err != nil {
			cancel()
			return nil, fmt.Errorf("persist recovery fence: %w", err)
		}
		i.record = r
		m.active[r.ID] = i
	}
	go m.reaper()
	m.notify()
	return m, nil
}

func newInstance(r Record) *instance {
	idle := make(chan struct{})
	close(idle)
	prepared := make(chan struct{})
	close(prepared)
	return &instance{record: r, tenantID: r.TenantID, prepared: prepared, jobs: make(map[string]*execution), idle: idle}
}

func token() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func normalizeCreate(req CreateRequest) (CreateRequest, error) {
	if req.TTLMS == 0 {
		req.TTLMS = 300_000
	}
	if req.Limits.MaxExecMS == 0 {
		req.Limits.MaxExecMS = 5_000
	}
	if req.Limits.MaxOutputBytes == 0 {
		req.Limits.MaxOutputBytes = 16_384
	}
	if req.Limits.MaxJobs == 0 {
		req.Limits.MaxJobs = 64
	}
	if req.TTLMS < 1 || req.TTLMS > 86_400_000 ||
		req.Limits.MaxExecMS < 1 || req.Limits.MaxExecMS > 60_000 ||
		req.Limits.MaxOutputBytes < 1 || req.Limits.MaxOutputBytes > 65_536 ||
		req.Limits.MaxJobs < 1 || req.Limits.MaxJobs > 256 {
		return req, fmt.Errorf("%w: TTL or execution limits out of range", ErrInvalid)
	}
	return req, nil
}

// Create is a trusted local-controller entry point. HTTP uses CreateScoped.
func (m *Manager) Create(ctx context.Context, req CreateRequest) (Record, error) {
	return m.CreateScoped(ctx, Owner{TenantID: "local", MaxInstances: m.opts.MaxInstances}, "", req)
}

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func createHashes(key string, req CreateRequest) (string, string, error) {
	if key == "" {
		return "", "", nil
	}
	if len(key) > 128 {
		return "", "", ErrInvalid
	}
	for _, c := range []byte(key) {
		if c < 33 || c > 126 {
			return "", "", ErrInvalid
		}
	}
	data, err := json.Marshal(req)
	if err != nil {
		return "", "", err
	}
	keySum, specSum := sha256.Sum256([]byte(key)), sha256.Sum256(data)
	return hex.EncodeToString(keySum[:]), hex.EncodeToString(specSum[:]), nil
}

// CreateScoped reserves ownership, tenant quota, and idempotency atomically.
// Completed tombstones retain keys: a retry never creates a fresh generation.
func (m *Manager) CreateScoped(ctx context.Context, owner Owner, key string, req CreateRequest) (Record, error) {
	if !owner.Valid() {
		return Record{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	req, err := normalizeCreate(req)
	if err != nil {
		return Record{}, err
	}
	keyHash, specHash, err := createHashes(key, req)
	if err != nil {
		return Record{}, err
	}
	id, err := token()
	if err != nil {
		return Record{}, err
	}
	generation, err := token()
	if err != nil {
		return Record{}, err
	}
	now := time.Now().UTC()
	i := newInstance(Record{
		Ref: Ref{ID: id, Generation: generation}, Backend: m.driver.Name(),
		TenantID: owner.TenantID, CreateKeyHash: keyHash, CreateSpecHash: specHash,
		State: Creating, Limits: req.Limits, CreatedAt: now, UpdatedAt: now,
		ExpiresAt: now.Add(time.Duration(req.TTLMS) * time.Millisecond),
	})
	i.prepared = make(chan struct{})
	defer close(i.prepared)
	i.opMu.Lock()
	defer i.opMu.Unlock()
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return Record{}, ErrClosing
	}
	index := owner.TenantID + "\x00" + keyHash
	if keyHash != "" {
		if existing := m.createKeys[index]; existing != nil {
			m.mu.Unlock()
			select {
			case <-ctx.Done():
				return Record{}, ctx.Err()
			case <-existing.prepared:
			}
			existing.mu.Lock()
			defer existing.mu.Unlock()
			r := existing.record
			if r.CreateSpecHash != specHash {
				return Record{}, ErrIdempotencyConflict
			}
			if r.State != Ready || r.DeleteRequested || !time.Now().Before(r.ExpiresAt) {
				return Record{}, ErrIdempotencyGone
			}
			return r, nil
		}
	}
	if len(m.active) >= m.opts.MaxInstances {
		m.mu.Unlock()
		return Record{}, ErrCapacity
	}
	tenantActive := 0
	for _, active := range m.active {
		if active.tenantID == owner.TenantID {
			tenantActive++
		}
	}
	if tenantActive >= owner.MaxInstances {
		m.mu.Unlock()
		return Record{}, ErrTenantCapacity
	}
	if m.records[id] != nil {
		m.mu.Unlock()
		return Record{}, errors.New("random identity collision")
	}
	m.records[id], m.active[id] = i, i
	if keyHash != "" {
		m.createKeys[index] = i
	}
	m.mu.Unlock()
	// Ownership is durable BEFORE the driver can allocate any resource.
	i.mu.Lock()
	ref := i.record.Ref
	err = m.store.Save(i.record)
	i.mu.Unlock()
	if err != nil {
		// Save may have committed before reporting a durability error. Keep the
		// reservation and key fenced until idempotent cleanup is confirmed.
		i.mu.Lock()
		next := i.record
		next.State, next.DeleteRequested, next.LastError = Stopping, true, "ownership persistence failed"
		m.fenceLocked(i, next)
		i.mu.Unlock()
		m.notify()
		return Record{}, fmt.Errorf("persist ownership before prepare: %w", err)
	}
	opCtx, cancel := context.WithTimeout(m.ctx, m.opts.OperationTimeout)
	stopCancel := context.AfterFunc(ctx, cancel)
	err = m.driver.Prepare(opCtx, ref, req.Limits)
	stopCancel()
	cancel()
	i.mu.Lock()
	if err == nil && (i.record.DeleteRequested || !time.Now().Before(i.record.ExpiresAt)) {
		err = fmt.Errorf("creation was fenced or expired")
	}
	if err == nil {
		next := i.record
		next.State = Ready
		err = m.saveLocked(i, next)
	}
	if err != nil {
		next := i.record
		next.State, next.DeleteRequested, next.LastError = Stopping, true, err.Error()
		// Keep an in-memory fence even if persistence is temporarily failing.
		m.fenceLocked(i, next)
	}
	r := i.record
	i.mu.Unlock()
	if err != nil {
		m.notify()
		return r, fmt.Errorf("create failed; cleanup scheduled: %w", err)
	}
	return r, nil
}

func (m *Manager) lookup(id string) (*instance, error) {
	m.mu.Lock()
	i := m.records[id]
	m.mu.Unlock()
	if i == nil {
		return nil, ErrNotFound
	}
	return i, nil
}

func (m *Manager) Get(id string) (Record, error) {
	i, err := m.lookup(id)
	if err != nil {
		return Record{}, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.record, nil
}

func (m *Manager) Exec(id string, req ExecRequest) (Job, error) {
	if len(req.Argv) == 0 || len(req.Argv) > 128 || req.Argv[0] == "" {
		return Job{}, fmt.Errorf("%w: argv must contain 1..128 arguments", ErrInvalid)
	}
	size := 0
	for _, arg := range req.Argv {
		size += len(arg)
	}
	if size > 32_768 {
		return Job{}, fmt.Errorf("%w: argv exceeds 32768 bytes", ErrInvalid)
	}
	jobID, err := token()
	if err != nil {
		return Job{}, err
	}
	m.mu.Lock()
	closing := m.closing
	m.mu.Unlock()
	if closing {
		return Job{}, ErrClosing
	}
	i, err := m.lookup(id)
	if err != nil {
		return Job{}, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if req.Generation != i.record.Generation {
		return Job{}, ErrStale
	}
	if i.record.State != Ready || i.record.DeleteRequested || !time.Now().Before(i.record.ExpiresAt) {
		return Job{}, ErrNotReady
	}
	if len(i.jobs) >= i.record.Limits.MaxJobs {
		return Job{}, ErrJobLimit
	}
	if req.TimeoutMS == 0 {
		req.TimeoutMS = i.record.Limits.MaxExecMS
	}
	if req.TimeoutMS < 1 || req.TimeoutMS > i.record.Limits.MaxExecMS {
		return Job{}, fmt.Errorf("%w: execution timeout exceeds instance policy", ErrInvalid)
	}
	// Do not retain a caller-owned mutable slice across the asynchronous call.
	req.Argv = append([]string(nil), req.Argv...)
	ctx, cancel := context.WithTimeout(m.ctx, time.Duration(req.TimeoutMS)*time.Millisecond)
	e := &execution{job: Job{
		ID: jobID, Ref: i.record.Ref, Status: "RUNNING", StartedAt: time.Now().UTC(),
	}, cancel: cancel}
	if i.running == 0 {
		i.idle = make(chan struct{})
	}
	i.running++
	i.jobs[jobID] = e
	job := e.job
	limit := i.record.Limits.MaxOutputBytes
	go m.run(i, e, ctx, req, limit)
	return job, nil
}

func (m *Manager) run(i *instance, e *execution, ctx context.Context, req ExecRequest, limit int) {
	out, err := m.driver.Exec(ctx, e.job.Ref, req, limit)
	if err == nil {
		err = ctx.Err()
	}
	e.cancel()
	// Keep a total output bound even when a future driver returns too much data.
	if len(out.Stdout) > limit {
		out.Stdout, out.Truncated = out.Stdout[:limit], true
	}
	remaining := limit - len(out.Stdout)
	if len(out.Stderr) > remaining {
		out.Stderr, out.Truncated = out.Stderr[:remaining], true
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	e.job.Output, e.job.FinishedAt = out, time.Now().UTC()
	e.job.Status = "EXITED"
	if err != nil {
		e.job.Error, e.job.Output.ExitCode = err.Error(), -1
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			e.job.Status = "TIMED_OUT"
		case errors.Is(err, context.Canceled):
			e.job.Status = "CANCELLED"
		default:
			e.job.Status = "FAILED"
		}
	}
	i.running--
	if i.running == 0 {
		close(i.idle)
	}
}

func (m *Manager) GetJob(id, jobID string) (Job, error) {
	i, err := m.lookup(id)
	if err != nil {
		return Job{}, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	e := i.jobs[jobID]
	if e == nil {
		return Job{}, ErrNotFound
	}
	return e.job, nil
}

func (m *Manager) Stop(ctx context.Context, ref Ref) (Record, error) {
	i, err := m.lookup(ref.ID)
	if err != nil {
		return Record{}, err
	}
	i.opMu.Lock()
	defer i.opMu.Unlock()
	i.mu.Lock()
	if ref.Generation != i.record.Generation {
		i.mu.Unlock()
		return Record{}, ErrStale
	}
	i.mu.Unlock()
	err = m.stopLocked(ctx, i)
	i.mu.Lock()
	r := i.record
	i.mu.Unlock()
	if err != nil {
		m.failed(i, err)
		m.notify()
	}
	return r, err
}

// stopLocked is called with opMu held. Execution admission is fenced before the
// driver is asked to stop; STOPPED is committed only after all calls are drained.
func (m *Manager) stopLocked(ctx context.Context, i *instance) error {
	i.mu.Lock()
	if i.record.State == Stopped || i.record.State == Reclaiming || i.record.State == Destroyed {
		i.mu.Unlock()
		return nil
	}
	next := i.record
	next.State = Stopping
	err := m.fenceLocked(i, next)
	for _, e := range i.jobs {
		if e.job.Status == "RUNNING" {
			e.cancel()
		}
	}
	idle, ref := i.idle, i.record.Ref
	i.mu.Unlock()
	if err != nil {
		return err
	}
	opCtx, cancel := context.WithTimeout(ctx, m.opts.OperationTimeout)
	defer cancel()
	if err := m.driver.Stop(opCtx, ref); err != nil {
		return err
	}
	select {
	case <-opCtx.Done():
		return opCtx.Err()
	case <-idle:
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	next = i.record
	next.State, next.StoppedAt, next.LastError = Stopped, time.Now().UTC(), ""
	return m.saveLocked(i, next)
}

// Destroy durably accepts deletion and fences new work. It does not claim that
// execution or resource reclamation is already complete; callers poll Get.
func (m *Manager) Destroy(ref Ref) (Record, error) {
	i, err := m.lookup(ref.ID)
	if err != nil {
		return Record{}, err
	}
	i.mu.Lock()
	if ref.Generation != i.record.Generation {
		i.mu.Unlock()
		return Record{}, ErrStale
	}
	if i.record.State == Destroyed {
		r := i.record
		i.mu.Unlock()
		return r, nil
	}
	next := i.record
	next.DeleteRequested = true
	if next.State != Stopped && next.State != Reclaiming {
		next.State = Stopping
	}
	err = m.fenceLocked(i, next)
	for _, e := range i.jobs {
		if e.job.Status == "RUNNING" {
			e.cancel()
		}
	}
	r := i.record
	i.mu.Unlock()
	m.notify()
	return r, err
}

func (m *Manager) reclaim(i *instance) error {
	i.opMu.Lock()
	defer i.opMu.Unlock()
	if err := m.stopLocked(m.ctx, i); err != nil {
		return err
	}
	i.mu.Lock()
	if i.record.State == Destroyed {
		i.mu.Unlock()
		return nil
	}
	next := i.record
	next.State = Reclaiming
	err := m.saveLocked(i, next)
	ref := i.record.Ref
	i.mu.Unlock()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(m.ctx, m.opts.OperationTimeout)
	err = m.driver.Cleanup(ctx, ref)
	cancel()
	if err != nil {
		return err
	}
	i.mu.Lock()
	next = i.record
	next.State, next.DestroyedAt, next.LastError = Destroyed, time.Now().UTC(), ""
	err = m.saveLocked(i, next)
	if err == nil {
		i.jobs = nil // Drop output history after reclamation; retain the tombstone.
	}
	i.mu.Unlock()
	if err == nil {
		m.mu.Lock()
		delete(m.active, ref.ID)
		m.mu.Unlock()
	}
	return err
}

func (m *Manager) saveLocked(i *instance, next Record) error {
	next.UpdatedAt = time.Now().UTC()
	if err := m.store.Save(next); err != nil {
		return err
	}
	i.record = next
	return nil
}

func (m *Manager) fenceLocked(i *instance, next Record) error {
	next.UpdatedAt = time.Now().UTC()
	i.record = next // Persistence failure must never reopen execution admission.
	return m.store.Save(next)
}

func (m *Manager) failed(i *instance, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.retryAt = time.Now().Add(m.opts.RetryDelay)
	next := i.record
	next.LastError = err.Error()
	m.fenceLocked(i, next)
}

func (m *Manager) activeInstances() []*instance {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]*instance, 0, len(m.active))
	for _, i := range m.active {
		items = append(items, i)
	}
	return items
}

func (m *Manager) notify() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) reaper() {
	defer close(m.workerDone)
	ticker := time.NewTicker(m.opts.ReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
		for _, i := range m.activeInstances() {
			if m.ctx.Err() != nil {
				return
			}
			i.mu.Lock()
			r, retryAt := i.record, i.retryAt
			i.mu.Unlock()
			if time.Now().Before(retryAt) {
				continue
			}
			if !r.DeleteRequested && !time.Now().Before(r.ExpiresAt) {
				if _, err := m.Destroy(r.Ref); err != nil {
					m.failed(i, err)
					continue
				}
				r.DeleteRequested = true
			}
			var err error
			if r.DeleteRequested {
				err = m.reclaim(i)
			} else if r.State == Stopping {
				_, err = m.Stop(m.ctx, r.Ref)
			}
			if err != nil {
				m.failed(i, err)
			}
		}
	}
}

func (m *Manager) Stats() Stats {
	items := m.activeInstances()
	s := Stats{Backend: m.driver.Name(), Active: len(items), Capacity: m.opts.MaxInstances}
	for _, i := range items {
		i.mu.Lock()
		if i.record.DeleteRequested || i.record.State == Stopping || i.record.State == Reclaiming {
			s.Recovering++
		}
		i.mu.Unlock()
	}
	return s
}

// Close requests deletion of all active instances. If its deadline expires, the
// ledger remains available for next-start recovery; it never reports success.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closing = true
	m.mu.Unlock()
	for _, i := range m.activeInstances() {
		i.mu.Lock()
		ref := i.record.Ref
		i.mu.Unlock()
		m.Destroy(ref)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if m.Stats().Active == 0 {
			m.cancel()
			select {
			case <-m.workerDone:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		select {
		case <-ctx.Done():
			m.cancel()
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
