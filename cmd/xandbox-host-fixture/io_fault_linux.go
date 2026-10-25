//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

type fixtureAPIResult struct {
	err error
	ms  float64
}

type fixtureStopResult struct {
	observed bool
	ms       float64
	err      error
}

func observeFixtureStop(ref sandbox.Ref, began time.Time) <-chan fixtureStopResult {
	out := make(chan fixtureStopResult, 1)
	go func() {
		for time.Since(began) < 7*time.Second {
			empty, e := ownedGroupEmpty(ref)
			if e != nil || empty {
				out <- fixtureStopResult{empty, float64(time.Since(began).Microseconds()) / 1000, e}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		out <- fixtureStopResult{}
	}()
	return out
}

func fixtureAsync(call func() error) <-chan fixtureAPIResult {
	out := make(chan fixtureAPIResult, 1)
	go func() {
		start := time.Now()
		e := call()
		out <- fixtureAPIResult{e, float64(time.Since(start).Microseconds()) / 1000}
	}()
	return out
}
func awaitFixtureAPI(ctx context.Context, ch <-chan fixtureAPIResult) (fixtureAPIResult, error) {
	select {
	case r := <-ch:
		return r, nil
	case <-ctx.Done():
		return fixtureAPIResult{}, ctx.Err()
	}
}
func ownedGroupEmpty(r sandbox.Ref) (bool, error) {
	b, e := os.ReadFile(nodeGroup + "/" + r.ID + r.Generation + "/cgroup.events")
	if e != nil {
		return false, e
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "populated 0" {
			return true, nil
		}
		if line == "populated 1" {
			return false, nil
		}
	}
	return false, errors.New("missing owned execution domain observation")
}
func processStart(pid int) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	s := string(b)
	end := strings.LastIndex(s, ") ")
	if end < 0 {
		return "", errors.New("invalid private proc identity")
	}
	fields := strings.Fields(s[end+2:])
	if len(fields) <= 19 {
		return "", errors.New("short proc identity")
	}
	return fields[19], nil
}
func daemonBlockedStateFsync(pid int, identity string) (bool, error) {
	before, e := processStart(pid)
	if e != nil || before != identity {
		return false, errors.New("owned daemon identity changed")
	}
	base := fmt.Sprintf("/proc/%d", pid)
	entries, e := os.ReadDir(base + "/task")
	if e != nil {
		return false, e
	}
	if len(entries) > 256 {
		return false, errors.New("unexpected daemon thread count")
	}
	found := false
	for _, entry := range entries {
		task := base + "/task/" + entry.Name()
		status, e := os.ReadFile(task + "/status")
		if e != nil {
			continue
		}
		if !strings.Contains(string(status), "\nState:\tD (") {
			continue
		}
		raw, e := os.ReadFile(task + "/syscall")
		if e != nil {
			continue
		}
		f := strings.Fields(string(raw))
		if len(f) < 2 {
			continue
		}
		// x86_64: fsync=74, fdatasync=75. Observe the ordinary daemon,
		// not the fixture's separate direct-read probe or a patched store.
		if f[0] != "74" && f[0] != "75" {
			continue
		}
		fd, e := strconv.ParseUint(f[1], 0, 32)
		if e != nil {
			continue
		}
		path, e := os.Readlink(fmt.Sprintf("%s/fd/%d", base, fd))
		if e == nil && strings.HasPrefix(path, "/srv/state/") {
			found = true
		}
	}
	after, e := processStart(pid)
	if e != nil || after != identity {
		return false, errors.New("owned daemon identity changed during observation")
	}
	return found, nil
}

// ioFault keeps its control plane on initramfs/tmpfs/serial while the ENTIRE
// persistent /srv (ledger, owner, runtime, assets and already-open FDs) fails.
// The only block probe is a READ of our own L1 mapper, never a raw host write.
func (n *node) ioFault(ctx context.Context, m *stateMapper, phase string) (result map[string]any, retErr error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if n.quotaStateIO && (!n.quotaDriver || n.quotaSnapshot || n.mapper != m) {
		return nil, errors.New("fixed quota IO mapper/profile required")
	}
	if e := m.verify("linear", false); e != nil {
		return nil, e
	}
	if e := n.start(ctx); e != nil {
		return nil, e
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	r, e := n.create(ctx, key)
	if e != nil {
		return nil, e
	}
	if e = actualNestedVM(r.Ref); e != nil {
		return nil, e
	}
	u, e := n.execute(ctx, r.Ref, []string{"id", "-u"})
	if e != nil || strings.TrimSpace(u.Stdout) != "65534" {
		return nil, errors.New("wrong guest UID")
	}
	boot, e := n.execute(ctx, r.Ref, []string{"cat", "/proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, e
	}
	if strings.HasSuffix(phase, "-busy") {
		job, e := n.submit(ctx, r.Ref, []string{"sh", "-c", "echo ready > io-ready; sleep 120 & sleep 120 & wait"})
		if e != nil {
			return nil, e
		}
		if _, e = n.execute(ctx, r.Ref, []string{"sh", "-c", "while [ ! -f io-ready ]; do sleep 0.01; done"}); e != nil {
			return nil, e
		}
		live, e := n.job(ctx, r.Ref, job)
		if e != nil || live.Status != "RUNNING" {
			return nil, errors.New("busy guest not RUNNING before fault")
		}
	}
	receipt := nodeReceipt{Phase: phase, Ref: r.Ref, Key: key, L1Boot: n.boot, L2Boot: strings.TrimSpace(boot.Stdout)}
	if e = privateWrite("/srv/fixture/receipt.json", receipt); e != nil {
		return nil, e
	}
	var quotaOwner []byte
	var quotaObserved map[string]any
	if n.quotaStateIO {
		qr, observed, e := n.observeDriverQuota(r.Ref, "running", m)
		if e != nil {
			return nil, e
		}
		if e = privateWrite("/srv/fixture/driver-quota-receipt.json", qr); e != nil {
			return nil, e
		}
		quotaOwner, e = privatefile.Read("/srv/state/firecracker/"+r.ID+r.Generation+".json", 2048)
		if e != nil {
			return nil, e
		}
		quotaObserved = observed
	}
	disk, e := os.Open("/srv")
	if e != nil {
		return nil, e
	}
	e = unix.Syncfs(int(disk.Fd()))
	disk.Close()
	if e != nil {
		return nil, e
	}
	identity, e := processStart(n.process.Process.Pid)
	if e != nil {
		return nil, e
	}
	fd, e := unix.Open(stateDevice, unix.O_RDONLY|unix.O_DIRECT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	buffer, e := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if e != nil {
		return nil, e
	}
	probe := make(chan error, 1)
	probeLaunched := false
	probeCollected := false
	restored := false
	// Restore the owned L1 mapper BEFORE waiting, closing, unmapping, logging or
	// returning. No fault path may leave a Go thread using an unmapped I/O buffer.
	defer func() {
		if !restored {
			if e := m.linear(); e != nil {
				retErr = errors.Join(retErr, e)
			}
		}
		if probeLaunched && !probeCollected {
			select {
			case <-probe:
			case <-time.After(5 * time.Second):
				retErr = errors.Join(retErr, errors.New("owned direct-read probe did not drain"))
				return
			}
		}
		clear(buffer)
		_ = unix.Munmap(buffer)
	}()
	hung := strings.HasPrefix(phase, "hang-")
	if hung {
		e = m.suspend()
	} else {
		e = m.setError()
	}
	if e != nil {
		return nil, e
	}
	probeLaunched = true
	go func() {
		count, e := unix.Pread(fd, buffer, 0)
		if e == nil && count != 4096 {
			e = errors.New("short owned direct read")
		}
		probe <- e
	}()
	result = map[string]any{"phase": phase, "real_nested_kvm": true, "guest_uid_checked": true, "checkpoint_receipt_fsynced": true, "whole_state_mapper_verified": true}
	for k, v := range quotaObserved {
		result[k] = v
	}
	if n.quotaStateIO {
		result["quota_mapped_mount_and_policy_checked_before_fault"] = true
	}
	if hung {
		select {
		case <-probe:
			probeCollected = true
			return nil, errors.New("suspended mapper unexpectedly completed direct read")
		case <-time.After(300 * time.Millisecond):
		}
		result["preopened_direct_read_blocked"] = true
	} else {
		select {
		case e = <-probe:
			probeCollected = true
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if !errors.Is(e, unix.EIO) {
			return nil, fmt.Errorf("owned mapper did not produce real EIO: %w", e)
		}
		result["preopened_direct_read_eio"] = true
	}
	apiCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	deleteBegan := time.Now()
	deletion := fixtureAsync(func() error {
		var out sandbox.Record
		return n.api.Do(apiCtx, "DELETE", nodePath(r.Ref), generationBody(r.Ref), &out)
	})
	stopping := observeFixtureStop(r.Ref, deleteBegan)
	var earlyDelete *fixtureAPIResult
	if hung {
		waitCtx, done := context.WithTimeout(ctx, 3*time.Second)
		e = waitNode(waitCtx, func() (bool, error) { return daemonBlockedStateFsync(n.process.Process.Pid, identity) })
		done()
		if e != nil {
			return nil, e
		}
		result["ordinary_daemon_state_fsync_observed_D"] = true
		select {
		case got := <-deletion:
			earlyDelete = &got
		default:
		}
		if earlyDelete != nil {
			return nil, errors.New("ordinary delete completed despite observed held fsync")
		}
		result["no_delete_ack_while_state_fsync_held"] = true
	} else {
		got, e := awaitFixtureAPI(ctx, deletion)
		if e != nil {
			return nil, e
		}
		earlyDelete = &got
		if got.err == nil || !strings.HasPrefix(got.err.Error(), "HTTP 500:") {
			return nil, errors.New("state EIO was falsely acknowledged or unexpected delete error")
		}
		result["delete_error_status"] = 500
		result["delete_error_ms"] = got.ms
	}
	execution := fixtureAsync(func() error {
		var out sandbox.Job
		return n.api.Do(apiCtx, "POST", nodePath(r.Ref)+"/exec", sandbox.ExecRequest{Generation: r.Generation, Argv: []string{"true"}}, &out)
	})
	// Retain the fault long enough to distinguish fast admission refusal from a
	// response queued behind a held ledger lock. This is a finite test guard.
	var earlyExec *fixtureAPIResult
	select {
	case got := <-execution:
		earlyExec = &got
	case <-time.After(1500 * time.Millisecond):
	}
	freshKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	var fresh sandbox.Record
	quotaCtx, quotaDone := context.WithTimeout(ctx, time.Second)
	e = n.api.Create(quotaCtx, freshKey, nodeSpec(), &fresh)
	quotaDone()
	if e == nil || !strings.HasPrefix(e.Error(), "HTTP 503:") {
		return nil, errors.New("faulted instance capacity released or quota response unavailable")
	}
	result["capacity_retained_new_create_503"] = true
	var stop fixtureStopResult
	select {
	case stop = <-stopping:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if stop.err != nil {
		return nil, stop.err
	}
	result["host_stop_observed_during_fault"] = stop.observed
	if stop.observed {
		result["delete_to_host_empty_observed_ms"] = stop.ms
	}
	result["host_stop_1500ms_guard_passed"] = stop.observed && stop.ms <= 1500
	if hung {
		// Recheck the independent evidence immediately before recovery, not merely
		// the fact that a sleep or client timeout elapsed.
		if e = m.verify("linear", true); e != nil {
			return nil, e
		}
		blocked, e := daemonBlockedStateFsync(n.process.Process.Pid, identity)
		if e != nil || !blocked {
			return nil, errors.New("ordinary state fsync no longer held before resume")
		}
		select {
		case <-probe:
			probeCollected = true
			return nil, errors.New("direct probe completed before mapper resume")
		default:
		}
	}
	if e = m.linear(); e != nil {
		return nil, e
	}
	restored = true
	if hung {
		select {
		case e = <-probe:
			probeCollected = true
			if e != nil {
				return nil, e
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		result["direct_read_completed_only_after_resume"] = true
	}
	var del fixtureAPIResult
	if earlyDelete != nil {
		del = *earlyDelete
	} else {
		del, e = awaitFixtureAPI(ctx, deletion)
		if e != nil {
			return nil, e
		}
	}
	if hung && del.err != nil {
		return nil, fmt.Errorf("delete did not finish after unstall: %w", del.err)
	}
	var exec fixtureAPIResult
	if earlyExec != nil {
		exec = *earlyExec
	} else {
		exec, e = awaitFixtureAPI(ctx, execution)
		if e != nil {
			return nil, e
		}
	}
	if exec.err == nil || !strings.HasPrefix(exec.err.Error(), "HTTP 409:") {
		return nil, errors.New("old execution admitted or wrong fence response")
	}
	result["new_exec_refused_409"] = true
	result["new_exec_refusal_ms"] = exec.ms
	result["new_exec_500ms_guard_passed"] = exec.ms <= 500
	if !hung {
		var current sandbox.Record
		if e = n.api.Do(ctx, "GET", nodePath(r.Ref), nil, &current); e != nil {
			return nil, e
		}
		if current.State != sandbox.Stopping || !current.StoppedAt.IsZero() || !current.DestroyedAt.IsZero() {
			return nil, errors.New("EIO produced false durable stop/destruction")
		}
		result["no_false_durable_stop_or_destroy_ack"] = true
	}
	if n.quotaStateIO {
		if hung {
			if e = waitNode(ctx, func() (bool, error) {
				var record sandbox.Record
				e := n.api.Do(ctx, "GET", nodePath(r.Ref), nil, &record)
				return e == nil && record.State == sandbox.Destroyed, e
			}); e != nil {
				return nil, e
			}
			if e = n.clean(r.Ref); e != nil {
				return nil, e
			}
			if e = driverQuotaAllClearOn(m); e != nil {
				return nil, e
			}
			if e = privateWrite("/srv/fixture/driver-quota-receipt.json", driverQuotaReceipt{Phase: "destroyed"}); e != nil {
				return nil, e
			}
			result["quota_and_ownership_released_only_after_io_resumed"] = true
		} else {
			after, e := privatefile.Read("/srv/state/firecracker/"+r.ID+r.Generation+".json", 2048)
			if e != nil || !bytes.Equal(after, quotaOwner) {
				return nil, errors.New("EIO prematurely changed quota ownership")
			}
			result["quota_owner_retained_until_cold_recovery"] = true
		}
	}
	result["underlying_mapper_restored_linear"] = true
	return result, nil
}
