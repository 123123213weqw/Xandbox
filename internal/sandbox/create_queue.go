package sandbox

import (
	"context"
	"errors"
)

// This queue arbitrates FUTURE instance capacity, not driver preparation slots.
// Raw and managed creates have identical priority. FIFO among eligible callers
// prevents a fresh arrival from stealing capacity from an admitted waiter.
// A tenant at its own live/metadata quota cannot head-of-line block others.
// Managed demand can start a queue; raw-only overload still fails fast. Raw
// may join an existing FIFO so a managed stream cannot monopolize all turns.
// No waiter owns a registered Ref, ledger key, project or capacity reservation.
type createWaiter struct {
	owner             Owner
	ctx               context.Context
	ticket            *CreationTicket
	managed           bool
	keyHash, specHash string
	admission         *Admission
}

// Equal, independent queue bounds for raw and managed work prevent either
// class from occupying every waiting position. Scheduling is still FIFO:
// neither class has priority or reserved VM capacity. A raw-only caller can
// use ALL configured instances. HTTP's own admission bound is separate.
// Bounds depend only on existing quotas, never client/test identities.
func (m *Manager) createClassQueueCapacity() int { return min(128, m.opts.MaxInstances) }
func (m *Manager) createQueueCapacity() int      { return 2 * m.createClassQueueCapacity() }
func (m *Manager) tenantCreateQueueCapacity(owner Owner) int {
	// Live capacity is not a licence to line up several different future
	// reservations. Raw and managed each get the same one-intent bulkhead.
	// Identical keyed retry callers retain the separate hard class bound.
	return min(1, m.createClassQueueCapacity(), owner.MaxInstances)
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
	n, class, tenantCallers := 0, 0, 0
	sameIntent := false
	for _, q := range m.createQueue {
		if q.managed == w.managed {
			class++
			if q.owner.TenantID == w.owner.TenantID {
				tenantCallers++
				// Identical keyed retries cannot allocate another future VM.
				// Keep their independent contexts/FIFO positions and original
				// hard caller bound; do not share cancellation or a ticket.
				if w.keyHash != "" && q.keyHash == w.keyHash && q.specHash == w.specHash && q.admission == w.admission && q.owner == w.owner {
					sameIntent = true
				} else {
					n++
				}
			}
		}
	}
	if class >= m.createClassQueueCapacity() {
		return ErrCapacity
	}
	// Retry equivalence does not waive the original per-tenant CALLER cap.
	// Otherwise one keyed retry flood could newly occupy a whole class.
	if tenantCallers >= min(m.createClassQueueCapacity(), w.owner.MaxInstances) {
		return ErrTenantCapacity
	}
	if !sameIntent && n >= m.tenantCreateQueueCapacity(w.owner) {
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

// reserveCreate never performs storage/driver I/O. A nil result means this
// request registered i exactly once; a nonnil result is an existing-key replay.
// Stop/Cleanup never acquire a preparation permit or join this demand queue.
func (m *Manager) reserveCreate(ctx, waitCtx context.Context, owner Owner, keyHash string, i *instance, ticket *CreationTicket) (*instance, error) {
	var waiter *createWaiter
	defer func() {
		if waiter != nil {
			m.mu.Lock()
			m.removeCreateWaiterLocked(waiter)
			m.mu.Unlock()
		}
	}()
	index := owner.TenantID + "\x00" + keyHash
	for {
		m.mu.Lock()
		if m.closing {
			m.mu.Unlock()
			return nil, ErrClosing
		}
		if keyHash != "" {
			if existing := m.createKeys[index]; existing != nil {
				m.removeCreateWaiterLocked(waiter)
				m.mu.Unlock()
				return existing, nil
			}
		}
		gateChanged, gateErr := m.opts.AdmissionGate.inspect(ticket)
		if gateErr != nil {
			m.mu.Unlock()
			return nil, gateErr
		}
		if len(m.records) >= m.opts.MaxRecords {
			m.mu.Unlock()
			return nil, ErrMetadataCapacity
		}
		if m.tenantRecords[owner.TenantID] >= m.opts.MaxTenantRecords {
			m.mu.Unlock()
			return nil, ErrTenantMetadataCapacity
		}
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			return nil, err
		}
		counts := m.activeTenantsLocked()
		capacityErr := m.capacityErrorLocked(owner, counts)
		if waiter == nil && i.admission == nil && len(m.createQueue) == 0 && capacityErr != nil {
			m.mu.Unlock()
			return nil, capacityErr // Raw-only overload remains fail-fast.
		}
		if waitCtx.Err() != nil {
			m.mu.Unlock()
			if capacityErr != nil {
				return nil, capacityErr
			}
			return nil, ErrCapacity
		}
		first := m.firstCreateWaiterLocked(counts)
		if capacityErr == nil && (first == nil || first == waiter) {
			if m.records[i.ref.ID] != nil {
				m.mu.Unlock()
				return nil, errors.New("random identity collision")
			}
			err := m.opts.AdmissionGate.reserve(ticket, func() {
				m.records[i.ref.ID], m.active[i.ref.ID] = i, i
				m.metricRecords.Add(1)
				m.metricAllocated.Add(1)
				m.tenantRecords[owner.TenantID]++
				if keyHash != "" {
					m.createKeys[index] = i
				}
				if len(m.createQueue) != 0 {
					m.signalCreatesLocked()
				}
			})
			m.removeCreateWaiterLocked(waiter)
			m.mu.Unlock()
			return nil, err
		}
		if waiter == nil {
			waiter = &createWaiter{owner: owner, ctx: waitCtx, ticket: ticket, managed: i.admission != nil,
				keyHash: keyHash, specHash: i.record.CreateSpecHash, admission: i.admission}
			if err := m.enqueueCreateLocked(waiter); err != nil {
				m.mu.Unlock()
				return nil, err
			}
		}
		changed := m.createChanged
		m.mu.Unlock()
		select {
		case <-waitCtx.Done():
		case <-gateChanged:
		case <-changed:
		}
	}
}
