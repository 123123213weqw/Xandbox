package sandbox

import "context"

// Ownership is immutable. Resource identities are never reassigned, including
// after cleanup, so checking before a lifecycle call has no ownership TOCTOU.
func (m *Manager) authorize(tenant, id string) error {
	i, err := m.lookup(id)
	if err != nil || tenant == "" || i.tenantID != tenant {
		return ErrNotFound // Do not disclose another tenant's resource existence.
	}
	return nil
}

func (m *Manager) GetScoped(tenant, id string) (Record, error) {
	if err := m.authorize(tenant, id); err != nil {
		return Record{}, err
	}
	return m.Get(id)
}

func (m *Manager) ExecScoped(tenant, id string, req ExecRequest) (Job, error) {
	if err := m.authorize(tenant, id); err != nil {
		return Job{}, err
	}
	return m.Exec(id, req)
}

func (m *Manager) GetJobScoped(tenant, id, jobID string) (Job, error) {
	if err := m.authorize(tenant, id); err != nil {
		return Job{}, err
	}
	return m.GetJob(id, jobID)
}

func (m *Manager) StopScoped(ctx context.Context, tenant string, ref Ref) (Record, error) {
	if err := m.authorize(tenant, ref.ID); err != nil {
		return Record{}, err
	}
	return m.Stop(ctx, ref)
}

func (m *Manager) DestroyScoped(tenant string, ref Ref) (Record, error) {
	if err := m.authorize(tenant, ref.ID); err != nil {
		return Record{}, err
	}
	return m.Destroy(ref)
}
