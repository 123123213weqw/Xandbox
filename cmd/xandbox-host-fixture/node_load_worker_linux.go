//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

func nodeLoadMS(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func nodeLoadRaw(ctx context.Context, api *switchAPI, state *nodeLoadState, start time.Time, a nodeLoadArrival, kind int, exactQuota bool) (row nodeLoadRow, err error) {
	row = nodeLoadRow{Kind: kind, Index: a.Index, Phase: a.Phase, Tenant: a.Tenant, Outcome: "failed", Stage: "raw_create"}
	began := time.Now()
	due := start.Add(a.Offset)
	row.QueueMS = nodeLoadMS(began.Sub(due))
	defer func() { row.TotalMS = switchMS(began); row.FinishedMS = switchMS(start) }()
	if e := ctx.Err(); e != nil {
		return row, e
	}
	key, e := randomKey()
	if e != nil {
		return row, e
	}
	var record sandbox.Record
	origin := time.Now()
	outcome, e := nodeLoadCall(ctx, api, "POST", "/v1/sandboxes", key, nodeSpec(), &record, 201)
	row.ReplyMS = switchMS(origin)
	row.DueReplyMS = nodeLoadMS(time.Now().Sub(due))
	row.APIObserved = true
	if e != nil {
		return row, e
	}
	if outcome != "completed" {
		row.Outcome = outcome
		return row, nil
	}
	if !switchRefValid(record.Ref) || record.State != sandbox.Ready || record.Backend != "firecracker" || record.TenantID != nodeLoadTenants[a.Tenant] {
		return row, errors.New("ordinary load create did not return exact real Ready")
	}
	if e = state.addKey(nodeLoadKey{Kind: 0, Tenant: a.Tenant, Key: key, Ref: record.Ref}); e != nil {
		return row, e
	}
	row.Stage = "raw_fresh"
	if e = budgetVM(record.Ref); e != nil {
		return row, e
	}
	owner, _, e := budgetOwner(record.Ref)
	if e != nil {
		return row, e
	}
	out, e := api.executeVM(ctx, record.Ref, nodeLoadFreshCommand())
	row.FirstMS = switchMS(origin)
	if e != nil {
		return row, e
	}
	if _, e = switchGuestIdentity(out); e != nil {
		return row, e
	}
	row.Stage = "raw_work"
	if _, e = api.executeVM(ctx, record.Ref, nodeLoadWorkCommand()); e != nil {
		return row, e
	}
	row.Stage = "raw_busy"
	job, deadline, e := nodeLoadBusy(ctx, api, record.Ref, nil)
	if e != nil {
		return row, e
	}
	row.Stage = "raw_stop"
	stopOrigin := time.Now()
	type stopped struct {
		ms float64
		e  error
	}
	observed := make(chan stopped, 1)
	observeCtx, stopObserve := context.WithCancel(ctx)
	go func() {
		err := waitNode(observeCtx, func() (bool, error) { return nodeLoadDomainEmpty(record.Ref) })
		observed <- stopped{switchMS(stopOrigin), err}
	}()
	e = nodeOOMStop(ctx, api, record.Ref)
	row.StopReplyMS = switchMS(stopOrigin)
	if e != nil {
		stopObserve()
		<-observed
		return row, e
	}
	row.Stage = "raw_empty"
	result := <-observed
	stopObserve()
	row.EmptyMS = result.ms
	if result.e != nil {
		return row, result.e
	}
	if !time.Now().Before(deadline) {
		return row, errors.New("load Stop was not before original busy timeout")
	}
	row.Stage = "raw_destroy"
	if e = api.call(ctx, "DELETE", switchPath(record.Ref), "", generationBody(record.Ref), nil, 202); e != nil {
		return row, e
	}
	if e = budgetDestroyed(ctx, api, record.Ref); e != nil {
		return row, e
	}
	row.NamespaceMS = switchMS(stopOrigin)
	terminal, lookupErr := api.job(ctx, record.Ref, job)
	_, e = switchOldJobOutcome(terminal, lookupErr, switchRow{BusyProgress: true, BusyOldRunning: true, OldStoppedMS: row.EmptyMS, OldDestroyedMS: row.NamespaceMS, OldTimeoutMS: nodeLoadMS(deadline.Sub(stopOrigin))})
	if e != nil {
		return row, e
	}
	if exactQuota {
		// Only the explicitly quiescent serial tail has no competing UID/project
		// reuse. Active-load namespace latency is NOT relabeled full-quota GC.
		q, e := driverQuotaRead(owner.ProjectID)
		if e != nil || !quotaEmpty(q) {
			return row, errors.New("quiescent exact project was not fully cleared")
		}
		row.FullQuotaMS = switchMS(stopOrigin)
	}
	row.Stage = "raw_replay"
	if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 410); e != nil {
		return row, e
	}
	row.Outcome = "completed"
	return row, nil
}

type nodeLoadCanary struct {
	binding  session.Result
	boot     string
	born     time.Time
	attempts int
}

func (c *nodeLoadCanary) open(ctx context.Context, api *switchAPI, state *nodeLoadState, tenant int) (string, error) {
	key, e := randomKey()
	if e != nil {
		return "", e
	}
	var b session.Result
	outcome, e := nodeLoadCall(ctx, api, "POST", "/v1/sessions", key, nodeSpec(), &b, 201)
	if e != nil || outcome != "completed" {
		return outcome, e
	}
	if !hex32Pattern(b.ID) || !switchRefValid(b.Current) || b.Revision != 1 {
		return "", errors.New("new load session binding invalid")
	}
	if e = state.addKey(nodeLoadKey{Kind: 1, Tenant: tenant, Key: key, Session: b.ID, Ref: b.Current}); e != nil {
		return "", e
	}
	c.binding = b
	c.born = time.Now()
	c.attempts = 0
	if e = budgetVM(b.Current); e != nil {
		return "", e
	}
	if _, _, e = budgetOwner(b.Current); e != nil {
		return "", e
	}
	out, e := api.sessionExec(ctx, b, nodeLoadFreshCommand())
	if e != nil {
		return "", e
	}
	c.boot, e = switchGuestIdentity(out)
	if e != nil {
		return "", e
	}
	if _, e = api.sessionExec(ctx, b, nodeLoadWorkCommand()); e != nil {
		return "", e
	}
	return outcome, nil
}

func (c *nodeLoadCanary) close(ctx context.Context, api *switchAPI) error {
	if c.binding.ID == "" {
		return nil
	}
	if e := nodeLoadRevoke(ctx, api, c.binding); e != nil {
		return e
	}
	c.binding = session.Result{}
	c.boot = ""
	return nil
}

func (c *nodeLoadCanary) tick(ctx context.Context, api *switchAPI, state *nodeLoadState, start time.Time, a nodeLoadArrival) (row nodeLoadRow, err error) {
	row = nodeLoadRow{Kind: 1, Index: a.Index, Phase: a.Phase, Tenant: a.Tenant, Outcome: "failed", Stage: "canary_open"}
	began := time.Now()
	due := start.Add(a.Offset)
	row.QueueMS = nodeLoadMS(began.Sub(due))
	defer func() { row.TotalMS = switchMS(began); row.FinishedMS = switchMS(start) }()
	if e := ctx.Err(); e != nil {
		return row, e
	}
	// Rotate on attempt count AND wall age, preserving the existing64 history,
	// 300s TTL and60s execution budgets rather than stretching them for a soak.
	if c.binding.ID != "" && (c.attempts >= 8 || time.Since(c.born) >= 200*time.Second) {
		if e := c.close(ctx, api); e != nil {
			return row, e
		}
	}
	if c.binding.ID == "" {
		origin := time.Now()
		outcome, e := c.open(ctx, api, state, a.Tenant)
		row.ReplyMS = switchMS(origin)
		row.DueReplyMS = nodeLoadMS(time.Now().Sub(due))
		row.APIObserved = true
		if e != nil {
			return row, e
		}
		if outcome != "completed" {
			row.Outcome = outcome
			return row, nil
		}
	}
	row.Stage = "canary_start"
	old := c.binding
	oldBoot := c.boot
	job, deadline, e := nodeLoadBusy(ctx, api, old.Current, &old)
	if e != nil {
		return row, e
	}
	key, e := randomKey()
	if e != nil {
		return row, e
	}
	request := session.SwitchRequest{ExpectedRevision: old.Revision, Create: nodeSpec()}
	origin := time.Now()
	type stopped struct {
		ms float64
		e  error
	}
	observed := make(chan stopped, 1)
	observeCtx, cancelObserve := context.WithCancel(ctx)
	go func() {
		e := waitNode(observeCtx, func() (bool, error) { return nodeLoadDomainEmpty(old.Current) })
		observed <- stopped{switchMS(origin), e}
	}()
	row.Stage = "canary_switch"
	var next session.Result
	outcome, e := nodeLoadCall(ctx, api, "POST", "/v1/sessions/"+old.ID+"/switch", key, request, &next, 200)
	row.ReplyMS = switchMS(origin)
	row.StopReplyMS = row.ReplyMS
	row.DueReplyMS = nodeLoadMS(time.Now().Sub(due))
	row.APIObserved = true
	c.attempts++
	if e != nil {
		cancelObserve()
		<-observed
		return row, e
	}
	if outcome != "completed" {
		cancelObserve()
		<-observed
		row.Stage = "canary_release"
		// Refusal does not mean the old job stopped. Explicit ordinary guest
		// release ends only this fixed TEST workload; it is not counted as Stop.
		if e = nodeLoadReleaseBusy(ctx, api, old, job); e != nil {
			return row, e
		}
		row.Outcome = outcome
		return row, nil
	}
	if next.ID != old.ID || next.Previous != old.Current || next.Current == old.Current || !switchRefValid(next.Current) || next.Revision != old.Revision+1 || !next.Timings.Measured {
		cancelObserve()
		<-observed
		return row, errors.New("load switch binding or internal timing missing")
	}
	c.binding = next
	c.born = time.Now()
	if e = state.addKey(nodeLoadKey{Kind: 2, Tenant: a.Tenant, Key: key, Session: old.ID, Revision: old.Revision, Ref: next.Current}); e != nil {
		cancelObserve()
		<-observed
		return row, e
	}
	row.RevokeMS = next.Timings.AdmissionRevokedMS
	row.Stage = "canary_new"
	if e = budgetVM(next.Current); e != nil {
		cancelObserve()
		<-observed
		return row, e
	}
	if _, _, e = budgetOwner(next.Current); e != nil {
		cancelObserve()
		<-observed
		return row, e
	}
	out, e := api.sessionExec(ctx, next, nodeLoadFreshCommand())
	row.FirstMS = switchMS(origin)
	if e != nil {
		cancelObserve()
		<-observed
		return row, e
	}
	boot, e := switchGuestIdentity(out)
	if e != nil || boot == oldBoot {
		cancelObserve()
		<-observed
		return row, errors.New("old assigned load guest was restored")
	}
	c.boot = boot
	row.Stage = "canary_old_gc"
	stop := <-observed
	cancelObserve()
	row.EmptyMS = stop.ms
	if stop.e != nil {
		return row, stop.e
	}
	if !time.Now().Before(deadline) {
		return row, errors.New("canary old domain stopped after original busy timeout")
	}
	if e = budgetDestroyed(ctx, api, old.Current); e != nil {
		return row, e
	}
	row.NamespaceMS = switchMS(origin)
	terminal, lookupErr := api.job(ctx, old.Current, job)
	if _, e = switchOldJobOutcome(terminal, lookupErr, switchRow{BusyProgress: true, BusyOldRunning: true, OldStoppedMS: row.EmptyMS, OldDestroyedMS: row.NamespaceMS, OldTimeoutMS: nodeLoadMS(deadline.Sub(origin))}); e != nil {
		return row, e
	}
	row.Stage = "canary_replay"
	var replay session.Result
	if e = api.call(ctx, "POST", "/v1/sessions/"+old.ID+"/switch", key, request, &replay, 200); e != nil {
		return row, e
	}
	if replay.ID != next.ID || replay.Revision != next.Revision || replay.Current != next.Current || replay.Previous != next.Previous {
		return row, errors.New("load switch replay allocated another guest")
	}
	if e = api.call(ctx, "POST", "/v1/sessions/"+old.ID+"/exec", "", map[string]any{"revision": old.Revision, "argv": []string{"true"}}, nil, 409); e != nil {
		return row, e
	}
	if _, e = api.sessionExec(ctx, next, nodeLoadWorkCommand()); e != nil {
		return row, e
	}
	row.Outcome = "completed"
	return row, nil
}

func nodeLoadWorkerFailure(tenant int, row nodeLoadRow, e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, "private load worker failure", tenant, row.Kind, row.Index, row.Stage, e)
	}
}
