package sandbox

import "context"

// Admission is a trusted in-process capability, not a tenant credential. Its
// check runs at execution admission under the record mutex and MUST be bounded,
// nonblocking and free of I/O. A managed VM cannot use the plain Exec path.
// No capability survives restart: all old generations are fenced for recovery.
type Admission struct{ allow func(Ref) bool }

func NewAdmission(allow func(Ref) bool) *Admission {
	if allow == nil {
		return nil
	}
	return &Admission{allow: allow}
}

func NormalizeCreate(req CreateRequest) (CreateRequest, error) { return normalizeCreate(req) }

// CreateManagedScoped reserves a domain-separated key. reserved runs exactly
// once for a fresh reservation, BEFORE ownership fsync or allocation, outside
// Manager.mu/instance.mu. It MUST only capture the immutable Ref in memory (and
// may call RevokeScoped); it must not block, perform I/O or publish admission.
func (m *Manager) CreateManagedScoped(ctx context.Context, owner Owner, key string, req CreateRequest, admission *Admission, reserved func(Ref)) (Record, error) {
	if admission == nil || key == "" || reserved == nil {
		return Record{}, ErrInvalid
	}
	return m.createScoped(ctx, owner, key, req, admission, reserved)
}

func (m *Manager) ExecManagedScoped(tenant, id string, req ExecRequest, admission *Admission) (Job, error) {
	if err := m.authorize(tenant, id); err != nil {
		return Job{}, err
	}
	if admission == nil {
		return Job{}, ErrInvalid
	}
	return m.exec(id, req, admission)
}

// RevokeScoped is a volatile admission/deletion fence, not an HTTP 202 or stop
// proof. It never waits for a record/storage lock. Lifecycle persists the fence,
// proves host Stop and performs Cleanup; guardian renewal stops independently.
func (m *Manager) RevokeScoped(tenant string, ref Ref) error {
	i, err := m.lookup(ref.ID)
	if err != nil || tenant == "" || i.tenantID != tenant {
		return ErrNotFound
	}
	if i.ref != ref {
		return ErrStale
	}
	i.requestIntent(true)
	m.notify()
	return nil
}

// OwnsScoped checks immutable authority only, NOT liveness or reclamation.
func (m *Manager) OwnsScoped(tenant string, ref Ref) bool {
	i, err := m.lookup(ref.ID)
	return err == nil && tenant != "" && i.tenantID == tenant && i.ref == ref
}

// UsableScoped is an observation for idempotent replies, never an execution
// permit. ExecManagedScoped rechecks the capability and deadline at admission.
func (m *Manager) UsableScoped(tenant string, ref Ref) bool {
	m.mu.Lock()
	closing := m.closing
	m.mu.Unlock()
	if closing {
		return false
	}
	i, err := m.lookup(ref.ID)
	if err != nil || tenant == "" || i.tenantID != tenant || i.ref != ref {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.usable()
}

func (i *instance) usable() bool {
	return i.record.State == Ready && !i.record.DeleteRequested && i.intent.Load() == 0 && !i.leaseFailed.Load() && !i.expired()
}
