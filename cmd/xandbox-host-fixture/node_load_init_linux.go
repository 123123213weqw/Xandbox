//go:build linux && xandbox_host_fixture

package main

// TEST ONLY init duty for the fixed owned L1. Never wait(-1): os/exec owns
// direct controller/helper statuses. Only an already-dead, adopted, reserved-UID
// Firecracker in an exact DELETED instance cgroup is eligible for an exact wait.
import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const nodeLoadInitPeriod = 250 * time.Millisecond

type nodeLoadInitStats struct {
	Active bool   `json:"active"`
	Sweeps uint64 `json:"sweeps"`
	Reaped uint64 `json:"reaped"`
	Errors uint64 `json:"errors"`
}

// This immutable binding outlives no controller incarnation. Its gate also
// serializes read-only censuses with waits; a census never initiates a reap.
// No process identity or cgroup name is serialized, including on errors.
type nodeLoadInit struct {
	controller int
	start      string
	gate       chan struct{}
	cancel     context.CancelFunc
	done       chan struct{}
	stats      nodeLoadInitStats // guarded by gate
}

type nodeLoadZombie struct {
	pid        int
	identity   nodeLoadProcIdentity
	uid        uint64
	membership string
}

// Separate mechanism from the guarded OS binding for synthetic negative/race
// tests. These functions are never externally selectable or a runtime backend.
type nodeLoadInitIO struct {
	read func(string) ([]byte, error)
	list func() ([]string, error)
	wait func(int) (int, error)
}

func nodeLoadInitLock(ctx context.Context, gate chan struct{}) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gate:
		if e := ctx.Err(); e != nil {
			gate <- struct{}{}
			return e
		}
		return nil
	}
}

func (r *nodeLoadInit) controllerValid(read func(string) ([]byte, error)) error {
	b, e := read("/proc/" + strconv.Itoa(r.controller) + "/stat")
	p, parseErr := nodeLoadParseProcStat(r.controller, b)
	if e != nil || parseErr != nil || p.parent != 1 || p.state == 'Z' || p.state == 'X' || p.state == 'x' || strconv.FormatUint(p.start, 10) != r.start {
		return errors.New("owned init controller incarnation unavailable")
	}
	return nil
}

func (r *nodeLoadInit) candidate(pid int, read func(string) ([]byte, error)) (nodeLoadZombie, bool, error) {
	var zero nodeLoadZombie
	if pid <= 1 || pid == r.controller {
		return zero, false, nil // In particular, NEVER consume Cmd.Wait's status.
	}
	path := "/proc/" + strconv.Itoa(pid)
	b, e := read(path + "/stat")
	if os.IsNotExist(e) {
		return zero, false, nil
	}
	p, parseErr := nodeLoadParseProcStat(pid, b)
	if e != nil || parseErr != nil {
		return zero, false, errors.New("bounded init proc identity unavailable")
	}
	if p.state != 'Z' || p.parent != 1 || p.comm != "firecracker" || p.start == 0 {
		return zero, false, nil
	}
	b, e = read(path + "/status")
	uid, parseErr := nodeLoadProcEUID(b)
	if e != nil || parseErr != nil {
		return zero, false, errors.New("adopted init candidate UID unavailable")
	}
	if uid < 400000 || uid >= 400004 {
		return zero, false, nil
	}
	b, e = read(path + "/cgroup")
	if e != nil {
		return zero, false, errors.New("adopted init candidate membership unavailable")
	}
	scoped, deleted, unknown := nodeLoadProcMembership(b)
	if !scoped || !deleted || unknown {
		return zero, false, nil
	}
	return nodeLoadZombie{pid, p, uid, string(b)}, true, nil
}

// Caller holds gate. A zombie owned by this PID1 cannot reuse its PID before
// wait releases it. Re-read all ownership fields and the controller immediately
// before the exact nonblocking wait; no signals, cgroup/namespace/ledger writes,
// resource-limit changes, or retries of failed workload occur here.
func (r *nodeLoadInit) sweepOwned(ctx context.Context, ops nodeLoadInitIO) (reaped uint64, err error) {
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	if e := r.controllerValid(ops.read); e != nil {
		return 0, e
	}
	names, e := ops.list()
	if e != nil || len(names) > nodeLoadProcLimit {
		return 0, errors.New("bounded init proc enumeration unavailable")
	}
	for _, name := range names {
		if e := ctx.Err(); e != nil {
			return reaped, e
		}
		pid, e := strconv.Atoi(name)
		if e != nil || pid <= 1 || strconv.Itoa(pid) != name {
			continue
		}
		first, eligible, e := r.candidate(pid, ops.read)
		if e != nil {
			return reaped, e
		}
		if !eligible {
			continue
		}
		if e = r.controllerValid(ops.read); e != nil {
			return reaped, e
		}
		last, eligible, e := r.candidate(pid, ops.read)
		if e != nil || !eligible || first != last {
			return reaped, errors.New("adopted init candidate ownership changed")
		}
		if e = ctx.Err(); e != nil {
			return reaped, e
		}
		got, e := ops.wait(pid)
		if e != nil || got != pid {
			return reaped, errors.New("exact adopted init wait did not reap expected zombie")
		}
		reaped++
	}
	return reaped, r.controllerValid(ops.read)
}

func nodeLoadInitOS() nodeLoadInitIO {
	return nodeLoadInitIO{
		read: nodeLoadProcRead,
		list: func() ([]string, error) {
			dir, e := os.Open("/proc")
			if e != nil {
				return nil, e
			}
			defer dir.Close()
			names, e := dir.Readdirnames(nodeLoadProcLimit + 1)
			if e == io.EOF {
				e = nil
			}
			return names, e
		},
		wait: func(pid int) (int, error) {
			if pid <= 1 {
				return 0, errors.New("exact positive adopted PID required")
			}
			// Keep the guard at the final OS boundary too. This is never invoked
			// by native host tests or the untagged production executables.
			if e := requireNode(); e != nil {
				return 0, e
			}
			var status unix.WaitStatus
			return unix.Wait4(pid, &status, unix.WNOHANG, nil)
		},
	}
}

func (r *nodeLoadInit) sweep(ctx context.Context) error {
	if e := requireNode(); e != nil {
		return e
	}
	if e := nodeLoadInitLock(ctx, r.gate); e != nil {
		return e
	}
	defer func() { r.gate <- struct{}{} }()
	if !r.stats.Active || r.stats.Errors != 0 {
		return errors.New("owned init reaper unavailable")
	}
	count, e := r.sweepOwned(ctx, nodeLoadInitOS())
	r.stats.Sweeps++
	r.stats.Reaped += count
	if e != nil && ctx.Err() == nil {
		r.stats.Errors++ // Latch errors; no silent restart or successful retry.
	}
	return e
}

func (r *nodeLoadInit) healthy(ctx context.Context) error {
	if r == nil {
		return errors.New("owned init reaper absent")
	}
	if e := nodeLoadInitLock(ctx, r.gate); e != nil {
		return e
	}
	defer func() { r.gate <- struct{}{} }()
	if !r.stats.Active || r.stats.Errors != 0 {
		return errors.New("owned init reaper failed or stopped")
	}
	return nil
}

func (n *node) startNodeLoadInit(ctx context.Context, childDone <-chan struct{}) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !n.nodeLoad || !n.nodeBudget || !n.quotaDriver || n.nodeSnapshot || n.process == nil || n.process.Process == nil || n.loadInit != nil {
		return errors.New("fresh fixed owned init binding required")
	}
	if _, e := fixedNodeLoadConfig(); e != nil {
		return e
	}
	identity, e := processStart(n.process.Process.Pid)
	if e != nil {
		return e
	}
	watch, cancel := context.WithCancel(ctx)
	r := &nodeLoadInit{controller: n.process.Process.Pid, start: identity, gate: make(chan struct{}, 1), cancel: cancel, done: make(chan struct{}), stats: nodeLoadInitStats{Active: true}}
	r.gate <- struct{}{}
	if e = r.sweep(watch); e != nil {
		cancel()
		return e
	}
	n.loadInit = r
	go func() {
		defer close(r.done)
		defer cancel()
		defer func() {
			<-r.gate
			r.stats.Active = false
			r.gate <- struct{}{}
		}()
		tick := time.NewTicker(nodeLoadInitPeriod)
		defer tick.Stop()
		for {
			select {
			case <-watch.Done():
				return
			case <-childDone:
				return
			case <-tick.C:
				bounded, end := context.WithTimeout(watch, nodeLoadProbeBudget)
				e := r.sweep(bounded)
				end()
				if e != nil {
					return
				}
			}
		}
	}()
	return nil
}

func (r *nodeLoadInit) stop(ctx context.Context) error {
	if r == nil {
		return errors.New("owned init reaper absent at stop")
	}
	r.cancel()
	select {
	case <-r.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if e := nodeLoadInitLock(ctx, r.gate); e != nil {
		return e
	}
	defer func() { r.gate <- struct{}{} }()
	if r.stats.Active || r.stats.Errors != 0 {
		return errors.New("owned init reaper did not stop cleanly")
	}
	return nil
}

func (n *node) nodeLoadInitQuiesce(ctx context.Context) (nodeLoadCensus, error) {
	var last nodeLoadCensus
	if e := requireNode(); e != nil {
		return last, e
	}
	if !n.nodeLoad || n.loadInit == nil {
		return last, errors.New("fixed owned init quiescence required")
	}
	// This is outside the offered clock, not an added actor retry or cleanup.
	// A periodic sweep may not yet have run after the last ordinary destroy.
	bounded, cancel := context.WithTimeout(ctx, nodeLoadProbeBudget)
	defer cancel()
	e := waitNode(bounded, func() (bool, error) {
		if e := n.loadInit.sweep(bounded); e != nil {
			return false, e
		}
		last = n.nodeLoadPID1Census(bounded, n.loadInit.start)
		if e := n.loadInit.healthy(bounded); e != nil {
			return false, e
		}
		if last.AdoptedZombies != 0 || last.ManagedControllerDead {
			return false, errors.New("unexpected adopted or managed zombie at init quiescence")
		}
		return nodeLoadPreflightCensusValid(last) == nil && last.NodePIDs == last.ControlPIDs, nil
	})
	return last, e
}
