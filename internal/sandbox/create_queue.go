package sandbox

import "context"

// This queue arbitrates FUTURE instance capacity, not driver preparation slots.
// Raw and managed creates have identical priority. FIFO among eligible callers
// prevents a fresh arrival from stealing capacity from an admitted waiter.
// A tenant at its own live/metadata quota cannot head-of-line block others.
// Managed demand can start a queue; raw-only overload still fails fast. Raw
// may join an existing FIFO so a managed stream cannot monopolize all turns.
// No waiter owns a registered Ref, ledger key, project or capacity reservation.
type createWaiter struct {
	owner   Owner
	ctx     context.Context
	ticket  *CreationTicket
	managed bool
}

// Equal, independent queue bounds for raw and managed work prevent either
// class from occupying every waiting position. Scheduling is still FIFO:
// neither class has priority or reserved VM capacity. A raw-only caller can
// use ALL configured instances. HTTP's own admission bound is separate.
// Bounds depend only on existing quotas, never client/test identities.
func (m *Manager) createClassQueueCapacity() int { return min(128, m.opts.MaxInstances) }
func (m *Manager) createQueueCapacity() int      { return 2 * m.createClassQueueCapacity() }
func (m *Manager) tenantCreateQueueCapacity(owner Owner) int {
	return min(m.createClassQueueCapacity(), owner.MaxInstances)
}

func (m *Manager) signalCreatesLocked() {
	close(m.createChanged)
	m.createChanged = make(chan struct{})
}

func (m *Manager) removeCreateWaiterLocked(w *createWaiter) {
	for n, q := range m.createQueue {
		if q == w {
			copy(m.createQueue[n:], m.createQueue[n+1:])
			m.createQueue[len(m.createQueue)-1] = nil
			m.createQueue = m.createQueue[:len(m.createQueue)-1]
			m.metricCreateQueued.Add(-1)
			m.signalCreatesLocked()
			return
		}
	}
}

func (m *Manager) enqueueCreateLocked(w *createWaiter) error {
	if len(m.createQueue) >= m.createQueueCapacity() {
		return ErrCapacity
	}
	n, class := 0, 0
	for _, q := range m.createQueue {
		if q.managed == w.managed {
			class++
			if q.owner.TenantID == w.owner.TenantID {
				n++
			}
		}
	}
	if class >= m.createClassQueueCapacity() {
		return ErrCapacity
	}
	if n >= m.tenantCreateQueueCapacity(w.owner) {
		return ErrTenantCapacity
	}
	m.createQueue = append(m.createQueue, w)
	m.metricCreateQueued.Add(1)
	return nil
}

func (m *Manager) activeTenantsLocked() map[string]int {
	counts := make(map[string]int)
	for _, i := range m.active {
		counts[i.tenantID]++
	}
	return counts
}

func (m *Manager) capacityErrorLocked(owner Owner, counts map[string]int) error {
	if len(m.active) >= m.opts.MaxInstances {
		return ErrCapacity
	}
	if counts[owner.TenantID] >= owner.MaxInstances {
		return ErrTenantCapacity
	}
	return nil
}

func (m *Manager) firstCreateWaiterLocked(counts map[string]int) *createWaiter {
	if len(m.active) >= m.opts.MaxInstances || len(m.records) >= m.opts.MaxRecords {
		return nil
	}
	for _, q := range m.createQueue {
		if q.ctx.Err() != nil || m.tenantRecords[q.owner.TenantID] >= m.opts.MaxTenantRecords || m.capacityErrorLocked(q.owner, counts) != nil {
			continue
		}
		if _, err := m.opts.AdmissionGate.inspect(q.ticket); err == nil {
			return q
		}
	}
	return nil
}
