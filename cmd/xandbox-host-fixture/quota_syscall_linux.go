//go:build linux && xandbox_host_fixture

package main

// Fixed own-L1 syscall fault cases. No generic errno, syscall, PID, FD, path or
// project control is exposed. The ordinary driver alone sets/clears quotas.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

func (o *quotaNotifier) boundary(q quotaNotif) error {
	if e := requireNode(); e != nil {
		return e
	}
	ref, e := negativeLedgerRef(o.base, sandbox.Ref{})
	if e != nil {
		return e
	}
	if o.state.ref != (sandbox.Ref{}) && o.state.ref != ref {
		return errors.New("fault crossed generation boundary")
	}
	b, e := privatefile.Read(o.base+"/s/firecracker/"+ref.ID+ref.Generation+".json", 2048)
	if e != nil {
		return e
	}
	var owner clearWindowOwner
	if e = strictjson.Decode(b, &owner); e != nil {
		return e
	}
	index := -1
	for i, name := range quotaSyscallCases {
		if name == o.state.name {
			index = i
		}
	}
	if index < 0 || owner.Version != 3 || owner.Ref != ref || !owner.QuotaAttempted || owner.InitializationAttempted || owner.TemplateID != "" || owner.UID != 480000+4*index || owner.ProjectID != quotaFirst {
		return errors.New("durable attempted owner missing before injected syscall")
	}
	if e = quotaOwnerSelector(q, owner.ProjectID); e != nil {
		return e
	}
	if len(o.state.owner) > 0 && !bytes.Equal(o.state.owner, b) {
		return errors.New("retained owner changed while fault armed")
	}
	for _, path := range []string{o.runtimeRoot + "/j/firecracker/" + ref.ID + ref.Generation, "/sys/fs/cgroup/xandbox-sq-" + o.state.name + "/" + ref.ID + ref.Generation} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return errors.New("injected quota boundary has execution namespace")
		}
	}
	fs, e := openQuotaFS(false)
	if e != nil {
		return e
	}
	defer fs.file.Close()
	r, e := fs.get(quotaFirst)
	if e != nil {
		return e
	}
	empty := o.state.name == "reserve-set-eio" || o.state.name == "clear-sync-erofs" || o.state.name == "clear-read-eio"
	if empty {
		if !quotaEmpty(r) {
			return errors.New("expected empty kernel quota at exact injected boundary")
		}
	} else if r.BHard != 192<<10 || r.IHard != 128 || r.BSoft|r.ISoft|r.Space|r.Inodes|r.BTime|r.ITime != 0 {
		return errors.New("expected installed limits without usage at exact injected boundary")
	}
	o.state.ref = ref
	o.state.boundaryChecks++
	o.state.owner = append([]byte(nil), b...)
	return nil
}

func syscallGuestBoundary(cfg firecracker.Config, ref sandbox.Ref, daemon int) error {
	return syscallGuestBoundaryWithObserver(cfg, ref, daemon, true)
}
func syscallGuestBoundaryWithObserver(cfg firecracker.Config, ref sandbox.Ref, daemon int, observer bool) error {
	// Inspect only the immutable fixture child's threads and its exact domain.
	if e := requireNode(); e != nil {
		return e
	}
	procs, e := os.ReadFile(cfg.CgroupRoot + "/" + ref.ID + ref.Generation + "/cgroup.procs")
	if e != nil {
		return e
	}
	check := func(pid string, minimum int) error {
		tasks, e := os.ReadDir("/proc/" + pid + "/task")
		if e != nil {
			return e
		}
		if len(tasks) == 0 || len(tasks) > 128 {
			return errors.New("unexpected task count")
		}
		for _, task := range tasks {
			b, e := os.ReadFile("/proc/" + pid + "/task/" + task.Name() + "/status")
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return e
			}
			for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"} {
				v, e := capabilityPresent(string(b), field, unix.CAP_SYS_RESOURCE)
				if e != nil || v {
					return errors.New("observed task can bypass quota")
				}
			}
			if minimum > 0 && (!strings.Contains(string(b), "NoNewPrivs:\t1\n") || !strings.Contains(string(b), "Seccomp:\t2\n")) {
				return errors.New("observed task lost seccomp or NNP")
			}
			count := 0
			for _, line := range strings.Split(string(b), "\n") {
				f := strings.Fields(line)
				if len(f) == 2 && f[0] == "Seccomp_filters:" {
					count, e = strconv.Atoi(f[1])
					if e != nil {
						return e
					}
				}
			}
			if count < minimum {
				return errors.New("ordinary filter plus observer layers missing")
			}
		}
		return nil
	}
	controllerMinimum := 0
	if observer {
		controllerMinimum = 1
	}
	if e = check(strconv.Itoa(daemon), controllerMinimum); e != nil {
		return e
	}
	vmm := false
	for _, pid := range strings.Fields(string(procs)) {
		fds, e := os.ReadDir("/proc/" + pid + "/fd")
		if e != nil {
			return e
		}
		actual := false
		for _, fd := range fds {
			target, _ := os.Readlink("/proc/" + pid + "/fd/" + fd.Name())
			if strings.Contains(target, "kvm-vm") {
				actual = true
			}
		}
		minimum := 1
		if observer {
			minimum++
		}
		if actual {
			minimum++
			vmm = true
		}
		if e = check(pid, minimum); e != nil {
			return e
		}
	}
	if !vmm {
		return errors.New("real KVM VM FD missing from fixed execution domain")
	}
	return nil
}
func (n *node) quotaSyscallSetup(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaDriver || n.quotaSnapshot || n.mapper != nil || n.process != nil {
		return nil, errors.New("fresh fixed cold quota profile required")
	}
	for _, path := range []string{"/srv/sq", "/srv/sr", "/srv/state/firecracker/config.json"} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return nil, errors.New("syscall setup refuses existing resources or binding")
		}
	}
	for _, path := range []string{"/srv/sq", "/srv/sr"} {
		if e := os.Mkdir(path, 0700); e != nil {
			return nil, e
		}
	}
	q, e := openQuotaFS(false)
	if e != nil {
		return nil, e
	}
	defer q.file.Close()
	if e = negativeQuotaClear(q); e != nil {
		return nil, e
	}
	b, e := os.ReadFile("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	var seed firecracker.Config
	if e = strictjson.Decode(b, &seed); e != nil {
		return nil, e
	}
	if seed.Version != 1 || seed.Quota == nil || seed.Snapshot != nil {
		return nil, errors.New("fixed cold quota policy required")
	}
	results := []map[string]any{}
	for index, name := range quotaSyscallCases {
		result, e := n.quotaSyscallCase(ctx, q, seed, index, name)
		if e != nil {
			return nil, fmt.Errorf("fixed syscall case %s: %w", name, e)
		}
		results = append(results, result)
	}
	return map[string]any{"test_only_syscall_errno_injection": true, "ordinary_daemon_elf_unchanged": true, "not_physical_media_fault": true, "all_fixed_syscall_cases": results, "all_fixed_projects_cleared": true, "repeated_clear_minimum": 3}, nil
}
func (n *node) quotaSyscallCase(ctx context.Context, q *quotaFS, seed firecracker.Config, index int, name string) (result map[string]any, err error) {
	base, e := quotaSyscallBase(name)
	if e != nil {
		return nil, e
	}
	runtimeRoot, e := quotaSyscallRuntime(name)
	if e != nil {
		return nil, e
	}
	if e = negativeQuotaClear(q); e != nil {
		return nil, e
	}
	for _, path := range []string{base, base + "/s"} {
		if e = os.Mkdir(path, 0700); e != nil {
			return nil, e
		}
	}
	cfg := seed
	quota := *seed.Quota
	cfg.Quota = &quota
	cfg.RuntimeRoot = runtimeRoot
	cfg.CgroupRoot = "/sys/fs/cgroup/xandbox-sq-" + name
	cfg.UIDStart = 480000 + index*4
	cfg.UIDCount = 3
	cfg.Quota.ProjectStart = quotaFirst
	if e = os.Mkdir(cfg.CgroupRoot, 0700); e != nil {
		return nil, e
	}
	if e = os.WriteFile(cfg.CgroupRoot+"/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); e != nil {
		return nil, e
	}
	if e = privateWrite(base+"/backend.json", cfg); e != nil {
		return nil, e
	}
	p, o, e := startQuotaNotified(ctx, name, runtimeRoot)
	if e != nil {
		return nil, e
	}
	defer func() {
		stopErr := p.stop()
		observerErr := o.close()
		if err == nil {
			if stopErr != nil {
				err = stopErr
			} else if observerErr != nil {
				err = observerErr
			}
		}
		if err != nil {
			if f, e := os.Open(base + "/first.log"); e == nil {
				defer f.Close()
				if st, e := f.Stat(); e == nil && st.Size() > 8192 {
					f.Seek(st.Size()-8192, 0)
				}
				io.CopyN(os.Stderr, f, 8192)
			}
		}
	}()
	api := client.NewWithToken(base+"/s/api.sock", n.token)
	defer api.Close()
	if e = negativeReady(ctx, p, api); e != nil {
		return nil, e
	}
	worker := &node{api: api}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	var old sandbox.Record
	reserve := strings.HasPrefix(name, "reserve-")
	if reserve {
		o.arm()
		if e = api.Create(ctx, key, nodeSpec(), &old); e == nil || !strings.Contains(e.Error(), "HTTP 500:") {
			return nil, errors.New("injected Prepare failure did not return500")
		}
	} else {
		old, e = worker.create(ctx, key)
		if e != nil {
			return nil, e
		}
		if e = syscallGuestBoundary(cfg, old.Ref, p.cmd.Process.Pid); e != nil {
			return nil, e
		}
		u, e := worker.execute(ctx, old.Ref, []string{"id", "-u"})
		if e != nil || strings.TrimSpace(u.Stdout) != "65534" {
			return nil, errors.New("wrong ordinary guest UID")
		}
		o.arm()
		var deleting sandbox.Record
		if e = api.Do(ctx, "DELETE", nodePath(old.Ref), generationBody(old.Ref), &deleting); e != nil {
			return nil, e
		}
	}
	if e = waitNode(ctx, func() (bool, error) {
		state := o.snapshot()
		minimum := 1
		if !reserve {
			minimum = 3
		}
		return state.injected >= minimum, state.err
	}); e != nil {
		return nil, e
	}
	state := o.snapshot()
	clearSetContinues := 0
	old.Ref = state.ref
	if !reserve {
		var held sandbox.Record
		if e = api.Do(ctx, "GET", nodePath(old.Ref), nil, &held); e != nil {
			return nil, e
		}
		if held.State != sandbox.Reclaiming || held.StoppedAt.IsZero() || !held.DestroyedAt.IsZero() {
			return nil, errors.New("faulted quota clear falsely released lifecycle ownership")
		}
		b, e := privatefile.Read(base+"/s/firecracker/"+old.ID+old.Generation+".json", 2048)
		if e != nil || !bytes.Equal(b, state.owner) {
			return nil, errors.New("quota clear fault lost durable owner")
		}
		newKey, e := randomKey()
		if e != nil {
			return nil, e
		}
		var refused sandbox.Record
		if e = api.Create(ctx, newKey, nodeSpec(), &refused); e == nil || !strings.Contains(e.Error(), "HTTP 503:") {
			return nil, errors.New("faulted quota clear released admission capacity")
		}
		// Each selected clear failure is rearmed after that attempt's SET.
		// Three replies are required; every reply rechecks the same owner,
		// namespace and kernel record, not just a timer-based sleep.
		clearSetContinues = state.qsetPassed
		if (name == "clear-set-eio" && clearSetContinues != 1) || (name != "clear-set-eio" && clearSetContinues < 4) {
			return nil, errors.New("clear target did not follow each attempt SET")
		}
		if state.injected < 3 || state.boundaryChecks < state.injected {
			return nil, errors.New("three validated clear error replies missing")
		}
		if e = quotaRetainedReclaiming(ctx, api, cfg, base, old.Ref, state.owner); e != nil {
			return nil, e
		}
		// Keep errno injection armed throughout all assertions, then CONTINUE.
		o.disarm()
	}
	if e = waitNode(ctx, func() (bool, error) {
		var r sandbox.Record
		e := api.Do(ctx, "GET", nodePath(old.Ref), nil, &r)
		return e == nil && r.State == sandbox.Destroyed, e
	}); e != nil {
		return nil, e
	}
	if e = negativeNoResources(cfg, base, old.Ref); e != nil {
		return nil, e
	}
	if e = negativeQuotaClear(q); e != nil {
		return nil, e
	}
	var refused sandbox.Record
	if e = api.Create(ctx, key, nodeSpec(), &refused); e == nil || !strings.Contains(e.Error(), "HTTP 410:") {
		return nil, errors.New("failed generation key reused")
	}
	freshKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	fresh, e := worker.create(ctx, freshKey)
	if e != nil {
		return nil, e
	}
	if e = syscallGuestBoundary(cfg, fresh.Ref, p.cmd.Process.Pid); e != nil {
		return nil, e
	}
	u, e := worker.execute(ctx, fresh.Ref, []string{"id", "-u"})
	if e != nil || strings.TrimSpace(u.Stdout) != "65534" {
		return nil, errors.New("fresh guest UID mismatch")
	}
	if _, e = worker.execute(ctx, fresh.Ref, []string{"true"}); e != nil {
		return nil, e
	}
	if e = worker.destroy(ctx, fresh.Ref); e != nil {
		return nil, e
	}
	if e = negativeNoResources(cfg, base, fresh.Ref); e != nil {
		return nil, e
	}
	if e = negativeQuotaClear(q); e != nil {
		return nil, e
	}
	state = o.snapshot()
	if state.err != nil {
		return nil, state.err
	}
	if state.injected < 1 || state.continued < 1 || (reserve && state.injected != 1) {
		return nil, errors.New("missing actual injected and continued kernel calls")
	}
	if e = p.stop(); e != nil {
		return nil, e
	}
	if e = os.Remove(cfg.CgroupRoot); e != nil {
		return nil, e
	}
	result = map[string]any{"case": name, "test_only_seccomp_errno": true, "fixed_child_thread_and_anchor_verified": true, "durable_attempted_owner_before_injection": true, "kernel_limits_and_zero_usage_checked_at_boundary": true, "no_execution_namespace_at_injected_boundary": true, "real_kernel_continue_not_emulated_success": true, "durable_destroyed_resources_absent_key410": true, "capacity_reused_fresh_real_kvm_guest_uid_exec_destroy": true, "all_thread_caps_nnp_observer_and_ordinary_vmm_filters_checked": true, "all_fixed_projects_cleared": true, "owned_cgroup_root_removed": true, "injected_calls": state.injected, "continued_kernel_calls": state.continued}
	if reserve {
		result["prepare_refused500"] = true
	} else {
		result["reclaiming_owner_and_capacity_retained_while_errno_armed"] = true
		result["new_create_refused503_during_clear_failure"] = true
		result["successful_set_continues_before_disarm"] = clearSetContinues
		result["at_least_three_clear_error_replies_before_disarm"] = true
		result["same_owner_namespace_and_kernel_record_checked_each_reply"] = true
		result["clear_target_rearmed_each_cleanup_attempt"] = true
		result["durable_reclaiming_ledger_checked_while_errors_armed"] = true
	}
	return result, nil
}
