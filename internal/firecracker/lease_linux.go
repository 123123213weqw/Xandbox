//go:build linux

package firecracker

import (
	"errors"
	"os"

	"github.com/123123213weqw/Xandbox/internal/hostclock"
	"github.com/123123213weqw/Xandbox/internal/lease"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

func newProcess(life *os.File, key string, hard int64) (*process, error) {
	binding, err := lease.ParseBinding(key)
	if err != nil {
		return nil, err
	}
	fd := int(life.Fd()) // Never call Fd again: it can restore blocking mode.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	p := &process{life: life, leaseFD: fd, binding: binding, hardDeadline: hard, done: make(chan struct{}), slots: make(chan struct{}, 2)}
	if err := p.refreshLease(); err != nil {
		return nil, err
	}
	return p, nil
}

// RefreshLease runs only on control reconciliation progress. It must never wait
// for disk, VM RPC, a pipe reader or a per-instance lifecycle/record lock.
func (d *driver) RefreshLease(ref sandbox.Ref) error {
	k, err := key(ref)
	if err != nil {
		return err
	}
	d.mu.Lock()
	p := d.procs[k]
	d.mu.Unlock()
	if p == nil {
		return nil
	} // No fork yet, or cleanup already proved destruction.
	return p.refreshLease()
}

func (p *process) refreshLease() error {
	if !p.leaseMu.TryLock() {
		return nil
	} // Skip contention; never extend locally.
	defer p.leaseMu.Unlock()
	if p.leaseClosed {
		return sandbox.ErrBackendFenced
	}
	now, err := hostclock.NowNS()
	if err != nil || now >= p.hardDeadline || now <= 0 {
		p.closeLeaseLocked()
		return sandbox.ErrBackendFenced
	}
	if now < p.nextRenew {
		return nil
	}
	if p.sequence == ^uint64(0) {
		p.closeLeaseLocked()
		return sandbox.ErrBackendFenced
	}
	frame := lease.Encode(p.binding, p.sequence+1, lease.Deadline(now, p.hardDeadline))
	n, err := unix.Write(p.leaseFD, frame[:]) // O_NONBLOCK + <= PIPE_BUF: atomic or fail.
	if err != nil || n != len(frame) {
		p.closeLeaseLocked()
		return errors.Join(sandbox.ErrBackendFenced, errors.New("guardian lease delivery failed"))
	}
	p.sequence++
	p.nextRenew = now + int64(lease.RenewInterval)
	return nil
}

func (p *process) closeLeaseLocked() {
	if !p.leaseClosed {
		p.leaseClosed = true
		_ = p.life.Close()
	}
}

func (p *process) closeLease() {
	p.leaseMu.Lock()
	defer p.leaseMu.Unlock()
	p.closeLeaseLocked()
}
