package sandbox

import (
	"sort"
	"time"

	"github.com/123123213weqw/Xandbox/internal/hostclock"
)

type workStage uint8

const (
	noWork workStage = iota
	stopWork
	cleanupWork
)

func stoppedState(s State) bool { return s == Stopped || s == Reclaiming || s == Destroyed }

// publish is called with instance.mu held (or before registration). The stop
// acknowledgement and its snapshot are immutable once published, so a Stop
// waiter need not queue behind a subsequent slow Cleanup on the same instance.
func (i *instance) publish() {
	i.leaseEligible.Store(i.record.State == Creating || i.record.State == Ready)
	i.recovering.Store(i.record.DeleteRequested || i.record.State == Stopping || i.record.State == Reclaiming)
	if stoppedState(i.record.State) {
		i.stopOnce.Do(func() { i.stoppedRecord = i.record; close(i.stopped) })
	}
}

func (i *instance) cancelWork() {
	if i.prepareCancel != nil {
		i.prepareCancel()
	}
	for _, e := range i.jobs {
		if e.job.Status == "RUNNING" {
			e.cancel()
		}
	}
}

// fenceIntent is an in-memory admission fence, not a durability acknowledgement.
// Stop workers persist it before stopping, cleanup workers persist RECLAIMING
// before deletion. Destroy's synchronous save still gates its HTTP 202.
func (i *instance) fenceIntent(deleteResources bool) {
	if i.record.State == Destroyed {
		return
	}
	i.record.DeleteRequested = i.record.DeleteRequested || deleteResources
	if !stoppedState(i.record.State) {
		i.record.State = Stopping
	}
	i.record.UpdatedAt = time.Now().UTC()
	i.cancelWork()
	i.publish()
}

func (i *instance) neededWork() workStage {
	if i.record.State == Destroyed {
		return noWork
	}
	if i.record.State == Stopping {
		return stopWork
	}
	if i.record.DeleteRequested {
		if stoppedState(i.record.State) {
			return cleanupWork
		}
		return stopWork
	}
	return noWork
}

func (m *Manager) startWorkers() {
	m.workers.Add(1 + m.opts.StopWorkers + m.opts.CleanupWorkers)
	go m.reaper()
	for range m.opts.StopWorkers {
		go m.workLoop(stopWork, m.stopQueue)
	}
	for range m.opts.CleanupWorkers {
		go m.workLoop(cleanupWork, m.cleanupQueue)
	}
	go func() { m.workers.Wait(); close(m.workerDone) }()
}

// Reconciliation only performs bounded nonblocking lease IPC, never storage/RPC I/O and never waits for an instance
// mutex. Saturation leaves durable/in-memory intent in the ledger; no ownership
// or capacity is dropped. A rotating cursor per pool prevents hot early IDs
// from repeatedly taking the only available queue slot ahead of older intents.
func (m *Manager) reaper() {
	defer m.workers.Done()
	ticker := time.NewTicker(m.opts.ReapInterval)
	defer ticker.Stop()
	cursors := make(map[workStage]string)
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
		items := m.activeInstances()
		sort.Slice(items, func(a, b int) bool { return items[a].ref.ID < items[b].ref.ID }) // Ref is immutable.
		m.mu.Lock()
		closing := m.closing
		m.mu.Unlock()
		for _, i := range items {
			if !closing && i.leaseEligible.Load() {
				if err := m.driver.RefreshLease(i.ref); err != nil {
					i.leaseFailed.Store(true)
				}
			}
		}
		for _, stage := range []workStage{stopWork, cleanupWork} {
			start := sort.Search(len(items), func(n int) bool { return items[n].ref.ID > cursors[stage] })
			for n := range items {
				if m.ctx.Err() != nil {
					return
				}
				i := items[(start+n)%len(items)]
				if !i.mu.TryLock() {
					continue
				}
				if !i.record.DeleteRequested && (closing || i.expired() || (i.leaseFailed.Load() && i.leaseEligible.Load())) {
					i.fenceIntent(true)
				}
				needed := i.neededWork()
				i.mu.Unlock()
				if needed == stage && m.enqueue(i, stage) {
					cursors[stage] = i.ref.ID
				}
			}
		}
	}
}

func (m *Manager) enqueue(i *instance, stage workStage) bool {
	m.workMu.Lock()
	defer m.workMu.Unlock()
	if i.work != noWork || time.Now().Before(i.retryAt) {
		return false
	}
	queue := m.stopQueue
	if stage == cleanupWork {
		queue = m.cleanupQueue
	}
	select {
	case queue <- i:
		i.work = stage
		return true
	default:
		return false
	}
}

func (m *Manager) deferWork(i *instance, delay time.Duration) {
	m.workMu.Lock()
	i.retryAt = time.Now().Add(delay)
	m.workMu.Unlock()
}

func (m *Manager) workLoop(stage workStage, queue <-chan *instance) {
	defer m.workers.Done()
	for {
		if m.ctx.Err() != nil {
			return
		}
		select {
		case <-m.ctx.Done():
			return
		case i := <-queue:
			m.perform(i, stage)
		}
	}
}

func (m *Manager) perform(i *instance, stage workStage) {
	delay := time.Duration(0)
	defer func() {
		m.workMu.Lock()
		i.work = noWork
		if delay > 0 {
			i.retryAt = time.Now().Add(delay)
		}
		m.workMu.Unlock()
		m.notify()
	}()
	if m.ctx.Err() != nil {
		return
	}
	if !i.opMu.tryAcquire() {
		delay = m.opts.ReapInterval // Never burn a pool slot waiting for Prepare/GC.
		return
	}
	defer i.opMu.release()
	running := &m.stopRunning
	if stage == cleanupWork {
		running = &m.cleanupRunning
	}
	running.Add(1)
	defer running.Add(-1)
	var err error
	if stage == stopWork {
		err = m.stopLocked(m.ctx, i)
	} else {
		err = m.cleanupLocked(i)
	}
	if err != nil {
		m.failed(i, err)
		delay = m.opts.RetryDelay
	}
}

// Clock failure is fail-closed. The kernel guardian also expires without renewal.
func (i *instance) expired() bool {
	now, err := hostclock.NowNS()
	return err != nil || i.expiresNS <= 0 || now >= i.expiresNS
}
