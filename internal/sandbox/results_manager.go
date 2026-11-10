package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The obligation/idle count covers the entire reservation IO and terminal IO,
// not merely guest execution. No result IO holds i.mu or the admission mutex.
// Stop can cancel/revoke the guest independently; a blocked fsync is never a
// successful stop/closure or a reason to start an unjournaled execution.
func (m *Manager) execWithResults(id string, req ExecRequest, admission *Admission) (Job, error) {
	if len(req.Argv) == 0 || len(req.Argv) > 128 || req.Argv[0] == "" {
		return Job{}, fmt.Errorf("%w: argv must contain 1..128 arguments", ErrInvalid)
	}
	size := 0
	for _, a := range req.Argv {
		if strings.IndexByte(a, 0) >= 0 {
			return Job{}, fmt.Errorf("%w: argv contains NUL", ErrInvalid)
		}
		size += len(a)
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
	if req.Generation != i.ref.Generation {
		return Job{}, ErrStale
	}
	if i.intent.Load() != 0 {
		return Job{}, ErrNotReady
	}
	i.mu.Lock()
	if req.Generation != i.record.Generation {
		i.mu.Unlock()
		return Job{}, ErrStale
	}
	if !i.usable() || i.admission != admission || admission != nil && !admission.allow(i.ref) {
		i.mu.Unlock()
		return Job{}, ErrNotReady
	}
	if len(i.jobs) >= i.record.Limits.MaxJobs {
		i.mu.Unlock()
		return Job{}, ErrJobLimit
	}
	if req.TimeoutMS == 0 {
		req.TimeoutMS = i.record.Limits.MaxExecMS
	}
	if req.TimeoutMS < 1 || req.TimeoutMS > i.record.Limits.MaxExecMS {
		i.mu.Unlock()
		return Job{}, fmt.Errorf("%w: execution timeout exceeds instance policy", ErrInvalid)
	}
	work, err := m.opts.AdmissionGate.acceptExecution()
	if err != nil {
		i.mu.Unlock()
		return Job{}, err
	}
	req.Argv = append([]string(nil), req.Argv...)
	ctx, cancel := context.WithTimeout(m.ctx, time.Duration(req.TimeoutMS)*time.Millisecond)
	e := &execution{job: Job{ID: jobID, Ref: i.record.Ref, Status: "RUNNING", StartedAt: time.Now().UTC()}, cancel: cancel, work: work}
	if i.running == 0 {
		i.idle = make(chan struct{})
	}
	i.running++
	i.jobs[jobID] = e
	limit := i.record.Limits.MaxOutputBytes
	h := ResultReservation{JobID: jobID, Ref: i.ref, TenantID: i.tenantID, MaxOutputBytes: limit, StartedAt: e.job.StartedAt}
	i.mu.Unlock()
	err = m.opts.Results.Reserve(h)
	if err == nil {
		err = ctx.Err()
	}
	i.mu.Lock()
	if err == nil && (!i.usable() || i.intent.Load() != 0 || i.admission != admission || admission != nil && !admission.allow(i.ref)) {
		err = ErrNotReady
	}
	if err != nil {
		// A reservation might be ambiguous. Do not erase it, release store capacity,
		// execute a command, expose output or synthesize a successful result.
		e.resultErr = ErrResultUnavailable
		e.job.Status = "RESULT_UNAVAILABLE"
		e.job.Error = "result retention unavailable"
		e.job.Output.ExitCode = -1
		e.job.FinishedAt = time.Now().UTC()
		i.running--
		if i.running == 0 {
			close(i.idle)
		}
		i.mu.Unlock()
		cancel()
		work.finish(false)
		if errors.Is(err, ErrResultCapacity) {
			return Job{}, ErrResultCapacity
		}
		return Job{}, ErrResultUnavailable
	}
	job := e.job
	i.mu.Unlock()
	go m.runWithResults(i, e, ctx, req, limit)
	return job, nil
}

func (m *Manager) runWithResults(i *instance, e *execution, ctx context.Context, req ExecRequest, limit int) {
	success := false
	defer func() { e.work.finish(success) }()
	out, err := m.driver.Exec(ctx, e.job.Ref, req, limit)
	if err == nil {
		err = ctx.Err()
	}
	e.cancel()
	if len(out.Stdout) > limit {
		out.Stdout = out.Stdout[:limit]
		out.Truncated = true
	}
	remaining := limit - len(out.Stdout)
	if len(out.Stderr) > remaining {
		out.Stderr = out.Stderr[:remaining]
		out.Truncated = true
	}
	out.Stdout, out.Stderr = strings.Clone(out.Stdout), strings.Clone(out.Stderr)
	i.mu.Lock()
	if errors.Is(err, ErrBackendFenced) && i.record.State == Ready {
		next := i.record
		next.State, next.DeleteRequested, next.LastError = Stopping, true, "backend requires recovery"
		_ = m.fenceLocked(i, next)
		for _, other := range i.jobs {
			if other.job.Status == "RUNNING" {
				other.cancel()
			}
		}
		m.notify()
	}
	job := e.job
	i.mu.Unlock()
	job.Output, job.FinishedAt, job.Status = out, time.Now().UTC(), "EXITED"
	if err != nil {
		job.Error = boundedLedgerError(err.Error())
		job.Output.ExitCode = -1
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			job.Status = "TIMED_OUT"
		case errors.Is(err, context.Canceled):
			job.Status = "CANCELLED"
		default:
			job.Status = "FAILED"
		}
	}
	// This IO is intentionally outside i.mu, before publication/idle/work-success.
	// A storage failure is sticky for this accepted obligation, never a retry or
	// a volatile output advertised as retained. Guest Stop remains independent.
	stored := m.opts.Results.Complete(job)
	i.mu.Lock()
	defer i.mu.Unlock()
	if stored != nil {
		e.resultErr = ErrResultUnavailable
		e.job.Output = Output{ExitCode: -1}
		e.job.Status = "RESULT_UNAVAILABLE"
		e.job.Error = "result retention unavailable"
		e.job.FinishedAt = job.FinishedAt
	} else {
		job.ResultRetained = true
		e.job = job
		success = err == nil && job.Output.ExitCode == 0
	}
	i.running--
	if i.running == 0 {
		close(i.idle)
	}
}
