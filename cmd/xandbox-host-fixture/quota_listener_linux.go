//go:build linux && xandbox_host_fixture

package main

// TEST ONLY. Lose the last seccomp listener at one of two fixed own-child SET
// boundaries. Never synthesize a response, target an arbitrary PID or reattach.
import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type quotaLossMode uint8

const (
	quotaLossReserve quotaLossMode = iota
	quotaLossRelease
)

func (m quotaLossMode) name() string {
	switch m {
	case quotaLossReserve:
		return "listener-loss-reserve"
	case quotaLossRelease:
		return "listener-loss-release"
	}
	return ""
}
func quotaLossName(name string) (quotaLossMode, bool) {
	for _, m := range []quotaLossMode{quotaLossReserve, quotaLossRelease} {
		if name == m.name() {
			return m, true
		}
	}
	return 0, false
}
func (m quotaLossMode) base() string {
	if m.name() == "" {
		return ""
	}
	return "/srv/sq/" + m.name()
}
func (m quotaLossMode) runtimeRoot() string {
	switch m {
	case quotaLossReserve:
		return "/srv/sr/7"
	case quotaLossRelease:
		return "/srv/sr/8"
	}
	return ""
}
func (m quotaLossMode) group() string {
	if m.name() == "" {
		return ""
	}
	return "/sys/fs/cgroup/xandbox-sq-" + m.name()
}
func (m quotaLossMode) uid() int {
	switch m {
	case quotaLossReserve:
		return 480028
	case quotaLossRelease:
		return 480032
	}
	return 0
}
func (m quotaLossMode) phase() string {
	switch m {
	case quotaLossReserve:
		return "reserve-quota-listener-loss"
	case quotaLossRelease:
		return "release-quota-listener-loss"
	}
	return ""
}
func (m quotaLossMode) recoveryChild() string {
	switch m {
	case quotaLossReserve:
		return "quota-listener-reserve-recover-daemon"
	case quotaLossRelease:
		return "quota-listener-release-recover-daemon"
	}
	return ""
}

const quotaLossReceiptPath = "/srv/fixture/quota-listener-receipt.json"

type quotaLossReceipt struct {
	Mode                            quotaLossMode
	Ref                             sandbox.Ref
	Key, L1Boot, L2Boot, ConfigHash string
	Owner                           []byte
}
type quotaLossPlan struct {
	Mode                          quotaLossMode
	Key, Boot, ConfigHash, L2Boot string
}
type quotaLossLive struct {
	p      *negativeDaemon
	o      *quotaNotifier
	api    *client.Client
	cancel context.CancelFunc
	done   chan error
}

func decodeQuotaLossOwner(mode quotaLossMode, b []byte, ref sandbox.Ref) error {
	var o clearWindowOwner
	if e := strictjson.Decode(b, &o); e != nil {
		return e
	}
	if mode.name() == "" || len(ref.ID) != 32 || len(ref.Generation) != 32 || strings.Trim(ref.ID+ref.Generation, "0123456789abcdef") != "" || o.Version != 3 || o.Ref != ref || o.UID != mode.uid() || o.ProjectID != quotaFirst || !o.QuotaAttempted || o.InitializationAttempted || o.TemplateID != "" {
		return errors.New("invalid fixed listener owner")
	}
	return nil
}
func quotaLossRecord(mode quotaLossMode, r quotaRecord) error {
	if mode.name() == "" {
		return errors.New("unknown listener mode")
	}
	if mode == quotaLossReserve {
		if !quotaEmpty(r) {
			return errors.New("unexecuted reserve SET changed quota")
		}
		return nil
	}
	if r.BHard != 192<<10 || r.IHard != 128 || r.BSoft|r.ISoft|r.Space|r.Inodes|r.BTime|r.ITime != 0 {
		return errors.New("unexecuted clear SET changed committed known limits")
	}
	return nil
}
func quotaLossNamespaceAbsent(mode quotaLossMode, ref sandbox.Ref) error {
	for _, p := range []string{mode.group() + "/" + ref.ID + ref.Generation, mode.runtimeRoot() + "/j/firecracker/" + ref.ID + ref.Generation} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return errors.New("listener boundary namespace remains")
		}
	}
	return nil
}
func fixedQuotaLossConfig(mode quotaLossMode) (firecracker.Config, error) {
	var cfg firecracker.Config
	if mode.name() == "" {
		return cfg, errors.New("unknown listener config")
	}
	b, e := privatefile.Read(mode.base()+"/backend.json", 8192)
	if e != nil {
		return cfg, e
	}
	if e = strictjson.Decode(b, &cfg); e != nil {
		return cfg, e
	}
	if cfg.Version != 1 || cfg.Snapshot != nil || cfg.RuntimeRoot != mode.runtimeRoot() || cfg.CgroupRoot != mode.group() || cfg.UIDStart != mode.uid() || cfg.UIDCount != 3 || !cfg.ReservedUIDRange || cfg.Quota == nil || cfg.Quota.ProjectStart != quotaFirst || cfg.Quota.MaxBytes != 192<<20 || cfg.Quota.MaxInodes != 128 {
		return cfg, errors.New("fixed listener policy changed")
	}
	return cfg, nil
}
func (o *quotaNotifier) prepareListenerLoss(q quotaNotif) error {
	if e := requireNode(); e != nil {
		return e
	}
	if o.loss == nil || o.loss.Mode.name() != o.state.name || o.state.lossClosed || q.Data.NR != int32(unix.SYS_QUOTACTL_FD) || q.Data.Args[1] != 0x80000802 {
		return errors.New("fixed listener SET required")
	}
	m := o.loss.Mode
	sets, syncs := 0, 0
	if m == quotaLossRelease {
		sets, syncs = 1, 2
	}
	if o.state.qsetPassed != sets || o.state.qsyncPassed != syncs {
		return errors.New("listener loss not at fixed reserve/clear SET ordinal")
	}
	ref, e := negativeLedgerRef(o.base, sandbox.Ref{})
	if e != nil {
		return e
	}
	b, e := privatefile.Read(o.base+"/s/firecracker/"+ref.ID+ref.Generation+".json", 2048)
	if e != nil {
		return e
	}
	if e = decodeQuotaLossOwner(m, b, ref); e != nil {
		return e
	}
	if e = quotaOwnerSelector(q, quotaFirst); e != nil {
		return e
	}
	if e = quotaLossNamespaceAbsent(m, ref); e != nil {
		return e
	}
	fs, e := openQuotaFS(false)
	if e != nil {
		return e
	}
	r, e := fs.get(quotaFirst)
	fs.file.Close()
	if e != nil {
		return e
	}
	if e = quotaLossRecord(m, r); e != nil {
		return e
	}
	if m == quotaLossReserve {
		if _, e = os.Lstat(quotaLossReceiptPath); !os.IsNotExist(e) {
			return errors.New("existing listener receipt")
		}
		if e = privateWrite(quotaLossReceiptPath, quotaLossReceipt{Mode: m, Ref: ref, Key: o.loss.Key, L1Boot: o.loss.Boot, ConfigHash: o.loss.ConfigHash, Owner: b}); e != nil {
			return e
		}
	} else if o.state.ref != ref || !bytes.Equal(o.state.owner, b) || !o.state.baselineSaved {
		return errors.New("release listener owner changed after pre-DELETE receipt")
	}
	o.state.ref = ref
	o.state.owner = append([]byte(nil), b...)
	o.state.baselineSaved = true
	o.exitTrace, e = o.startListenerExitTrace(q)
	return e
}

// Verify both the API view and one atomic, bounded durable ledger envelope.
// Never acquire another FileStore lock while the ordinary daemon owns it.
func quotaRetainedReclaiming(ctx context.Context, api *client.Client, cfg firecracker.Config, base string, ref sandbox.Ref, owner []byte) error {
	if e := requireNode(); e != nil {
		return e
	}
	if len(ref.ID) != 32 || len(ref.Generation) != 32 || strings.Trim(ref.ID+ref.Generation, "0123456789abcdef") != "" {
		return errors.New("invalid retained ref")
	}
	var r sandbox.Record
	if e := api.Do(ctx, "GET", nodePath(ref), nil, &r); e != nil {
		return e
	}
	valid := func(r sandbox.Record) bool {
		return r.Ref == ref && r.State == sandbox.Reclaiming && !r.StoppedAt.IsZero() && r.DestroyedAt.IsZero()
	}
	if !valid(r) {
		return errors.New("failed quota cleanup falsely destroyed ownership")
	}
	b, e := privatefile.Read(base+"/s/ledger/"+ref.ID+".json", 64<<10)
	if e != nil {
		return e
	}
	var envelope struct {
		Version int            `json:"version"`
		Record  sandbox.Record `json:"record"`
	}
	if e = strictjson.Decode(b, &envelope); e != nil {
		return e
	}
	if envelope.Version != 1 || !valid(envelope.Record) {
		return errors.New("durable reclaiming envelope not retained")
	}
	b, e = privatefile.Read(base+"/s/firecracker/"+ref.ID+ref.Generation+".json", 2048)
	if e != nil || !bytes.Equal(b, owner) {
		return errors.New("durable attempted owner changed while cleanup failed")
	}
	for _, p := range []string{cfg.RuntimeRoot + "/j/firecracker/" + ref.ID + ref.Generation, cfg.CgroupRoot + "/" + ref.ID + ref.Generation} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			return errors.New("failed clear still has namespace")
		}
	}
	key, e := randomKey()
	if e != nil {
		return e
	}
	var refused sandbox.Record
	if e = api.Create(ctx, key, nodeSpec(), &refused); e == nil || !strings.Contains(e.Error(), "HTTP 503:") {
		return errors.New("failed clear opened new frontend admission")
	}
	return nil
}
func (n *node) quotaListenerCheckpoint(ctx context.Context, mode quotaLossMode) (out map[string]any, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if mode.name() == "" || !n.quotaDriver || n.quotaSnapshot || n.mapper != nil || n.process != nil || n.quotaLost != nil {
		return nil, errors.New("fresh fixed quota listener profile required")
	}
	for _, p := range []string{"/srv/sq", "/srv/sr", quotaLossReceiptPath} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return nil, errors.New("existing listener scope")
		}
	}
	base := mode.base()
	for _, p := range []string{"/srv/sq", "/srv/sr", base, base + "/s", mode.group()} {
		if e := os.Mkdir(p, 0700); e != nil {
			return nil, e
		}
	}
	if e := os.WriteFile(mode.group()+"/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); e != nil {
		return nil, e
	}
	b, e := privatefile.Read("/srv/config/backend.json", 8192)
	if e != nil {
		return nil, e
	}
	var cfg firecracker.Config
	if e = strictjson.Decode(b, &cfg); e != nil {
		return nil, e
	}
	if cfg.Version != 1 || cfg.Snapshot != nil || cfg.Quota == nil {
		return nil, errors.New("fixed cold quota seed required")
	}
	cfg.RuntimeRoot = mode.runtimeRoot()
	cfg.CgroupRoot = mode.group()
	cfg.UIDStart = mode.uid()
	cfg.UIDCount = 3
	cfg.Quota.ProjectStart = quotaFirst
	if e = privateWrite(base+"/backend.json", cfg); e != nil {
		return nil, e
	}
	if _, e = fixedQuotaLossConfig(mode); e != nil {
		return nil, e
	}
	hash, e := fileHash(base + "/backend.json")
	if e != nil {
		return nil, e
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	plan := &quotaLossPlan{Mode: mode, Key: key, Boot: n.boot, ConfigHash: hash}
	liveCtx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	p, o, e := startQuotaNotifiedPlanned(liveCtx, mode.name(), cfg.RuntimeRoot, nil, nil, plan)
	if e != nil {
		cancel()
		return nil, e
	}
	api := client.NewWithToken(base+"/s/api.sock", n.token)
	live := &quotaLossLive{p: p, o: o, api: api, cancel: cancel, done: make(chan error, 1)}
	defer func() {
		if err != nil {
			cancel()
			_ = p.stop()
			_ = o.close()
			if o.exitTrace != nil {
				o.exitTrace.close()
			}
			api.Close()
		}
	}()
	if e = negativeReady(ctx, p, api); e != nil {
		return nil, e
	}
	worker := &node{api: api}
	if mode == quotaLossRelease {
		old, e := worker.create(ctx, key)
		if e != nil {
			return nil, e
		}
		if e = syscallGuestBoundary(cfg, old.Ref, p.cmd.Process.Pid); e != nil {
			return nil, e
		}
		u, e := worker.execute(ctx, old.Ref, []string{"id", "-u"})
		if e != nil || strings.TrimSpace(u.Stdout) != "65534" {
			return nil, errors.New("listener old guest UID mismatch")
		}
		boot, e := worker.execute(ctx, old.Ref, []string{"cat", "/proc/sys/kernel/random/boot_id"})
		if e != nil || strings.TrimSpace(boot.Stdout) == "" {
			return nil, errors.New("listener old guest boot missing")
		}
		plan.L2Boot = strings.TrimSpace(boot.Stdout)
		b, e := privatefile.Read(base+"/s/firecracker/"+old.ID+old.Generation+".json", 2048)
		if e != nil {
			return nil, e
		}
		if e = decodeQuotaLossOwner(mode, b, old.Ref); e != nil {
			return nil, e
		}
		fs, e := openQuotaFS(false)
		if e != nil {
			return nil, e
		}
		r, e := fs.get(quotaFirst)
		fs.file.Close()
		if e != nil || r.Space < 128<<20 || r.Space > 192<<20 || r.Inodes < 1 || r.Inodes > 128 || r.BHard != 192<<10 || r.IHard != 128 {
			return nil, errors.New("listener old guest is not quota charged")
		}
		for _, p := range []string{cfg.RuntimeRoot + "/j/firecracker/" + old.ID + old.Generation, cfg.RuntimeRoot + "/j/firecracker/" + old.ID + old.Generation + "/root", cfg.RuntimeRoot + "/j/firecracker/" + old.ID + old.Generation + "/root/workspace.ext4"} {
			a, e := quotaAttributes(p, nil)
			if e != nil || a.Project != quotaFirst {
				return nil, errors.New("listener live project changed")
			}
		}
		if e = privateWrite(quotaLossReceiptPath, quotaLossReceipt{Mode: mode, Ref: old.Ref, Key: key, L1Boot: n.boot, L2Boot: plan.L2Boot, ConfigHash: hash, Owner: b}); e != nil {
			return nil, e
		}
		o.mu.Lock()
		valid := o.state.qsetPassed == 1 && o.state.qsyncPassed == 1
		if valid {
			o.state.ref = old.Ref
			o.state.owner = append([]byte(nil), b...)
			o.state.baselineSaved = true
			o.state.armed = true
		}
		o.mu.Unlock()
		if !valid {
			return nil, errors.New("unexpected listener reserve sequence")
		}
		var accepted sandbox.Record
		if e = api.Do(ctx, "DELETE", nodePath(old.Ref), generationBody(old.Ref), &accepted); e != nil {
			return nil, e
		}
	} else {
		o.arm()
		go func() { var r sandbox.Record; live.done <- api.Create(liveCtx, key, nodeSpec(), &r) }()
	}
	if e = waitNode(ctx, func() (bool, error) {
		s := o.snapshot()
		select {
		case <-o.done:
			return s.lossClosed, s.err
		default:
			return false, s.err
		}
	}); e != nil {
		return nil, e
	}
	s := o.snapshot()
	if s.injected != 0 || s.err != nil || !s.baselineSaved || o.exitTrace == nil {
		return nil, errors.New("listener loss used an error reply or missed owner")
	}
	var actual quotaExitResult
	if e = waitNode(ctx, func() (bool, error) { var e error; actual, e = o.exitTrace.read(); return actual.Seen != 0, e }); e != nil {
		return nil, e
	}
	if actual.Seen != 1 || actual.Return != -int64(unix.ENOSYS) {
		return nil, errors.New("lost listener did not produce actual selected SET ENOSYS")
	}
	o.exitTrace.close()
	if mode == quotaLossReserve {
		select {
		case e = <-live.done:
			if e == nil || !strings.Contains(e.Error(), "HTTP 500:") {
				return nil, errors.New("lost listener Prepare did not return500")
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if e = waitNode(ctx, func() (bool, error) {
		var r sandbox.Record
		e := api.Do(ctx, "GET", nodePath(s.ref), nil, &r)
		return e == nil && r.State == sandbox.Reclaiming, e
	}); e != nil {
		return nil, e
	}
	fs, e := openQuotaFS(false)
	if e != nil {
		return nil, e
	}
	defer fs.file.Close()
	for i := 0; i < 3; i++ {
		if e = quotaRetainedReclaiming(ctx, api, cfg, base, s.ref, s.owner); e != nil {
			return nil, e
		}
		r, e := fs.get(quotaFirst)
		if e != nil {
			return nil, e
		}
		if e = quotaLossRecord(mode, r); e != nil {
			return nil, e
		}
		time.Sleep(100 * time.Millisecond)
	}
	n.quotaLost = live
	return map[string]any{"phase": mode.phase(), "fixed_owned_thread_anchor_owner_checked": true, "receipt_fsynced_before_target_set": true, "last_listener_closed_without_notification_response": true, "selected_quotactl_fd_kernel_exit_observed": true, "selected_set_kernel_errno": int(unix.ENOSYS), "first_return_latch_seen": actual.Seen, "target_set_not_continued_or_errno_emulated": true, "quota_and_absent_namespace_checked_before_listener_close": true, "durable_reclaiming_stopped_owner_and_admission503_rechecked_three_times": true, "quota_unchanged_while_listener_absent": true, "no_false_destroy_confirmation": true, "listener_never_reattached_before_power_cut": true, "prepare_refused500": mode == quotaLossReserve, "checkpoint_has_no_old_l2_vm": mode == quotaLossReserve, "old_real_kvm_uid_exec_quota_filters_checked": mode == quotaLossRelease, "delete_acceptance_allowed_not_destroy_confirmation": mode == quotaLossRelease}, nil
}
func runQuotaListenerRecoveryDaemon(mode quotaLossMode) error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedQuotaLossConfig(mode); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	base := mode.base()
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", base + "/s", "-auth-file", "/srv/config/auth.json", "-firecracker-config", base + "/backend.json", "-max-instances", "1"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}
func (n *node) quotaListenerRecover(ctx context.Context, mode quotaLossMode) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if mode.name() == "" || !n.quotaDriver || n.quotaSnapshot || n.mapper != nil || n.process != nil || n.quotaLost != nil {
		return nil, errors.New("fresh listener cold boot required")
	}
	b, e := privatefile.Read(quotaLossReceiptPath, 8192)
	if e != nil {
		return nil, e
	}
	var old quotaLossReceipt
	if e = strictjson.Decode(b, &old); e != nil {
		return nil, e
	}
	if old.Mode != mode || old.L1Boot == "" || old.L1Boot == n.boot || len(old.Key) != 64 || strings.Trim(old.Key, "0123456789abcdef") != "" || ((mode == quotaLossRelease) != (old.L2Boot != "")) {
		return nil, errors.New("invalid cold listener receipt")
	}
	if e = decodeQuotaLossOwner(mode, old.Owner, old.Ref); e != nil {
		return nil, e
	}
	cfg, e := fixedQuotaLossConfig(mode)
	if e != nil {
		return nil, e
	}
	base := mode.base()
	hash, e := fileHash(base + "/backend.json")
	if e != nil || hash != old.ConfigHash {
		return nil, errors.New("listener immutable policy changed")
	}
	b, e = privatefile.Read(base+"/s/firecracker/"+old.Ref.ID+old.Ref.Generation+".json", 2048)
	if e != nil || !bytes.Equal(b, old.Owner) {
		return nil, errors.New("listener attempted owner lost across cold boot")
	}
	if e = quotaLossNamespaceAbsent(mode, old.Ref); e != nil {
		return nil, e
	}
	fs, e := openQuotaFS(false)
	if e != nil {
		return nil, e
	}
	defer fs.file.Close()
	r, e := fs.get(quotaFirst)
	if e != nil {
		return nil, e
	}
	if e = quotaLossRecord(mode, r); e != nil {
		return nil, e
	}
	for id := quotaFirst + 1; id < quotaFirst+3; id++ {
		r, e := fs.get(id)
		if e != nil || !quotaEmpty(r) {
			return nil, errors.New("unrelated listener project changed")
		}
	}
	if e = os.Mkdir(mode.group(), 0700); e != nil {
		return nil, e
	}
	if e = os.WriteFile(mode.group()+"/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); e != nil {
		return nil, e
	}
	log, e := os.OpenFile("/srv/fixture/quota-listener-cold.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	c := exec.CommandContext(ctx, "/usr/bin/xandbox-host-fixture", "-mode", mode.recoveryChild())
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	c.Stdout, c.Stderr = log, log
	if e = c.Start(); e != nil {
		return nil, e
	}
	p := &negativeDaemon{cmd: c, done: make(chan struct{})}
	go func() { p.waitErr = c.Wait(); close(p.done) }()
	defer p.stop()
	api := client.NewWithToken(base+"/s/api.sock", n.token)
	defer api.Close()
	if e = negativeReady(ctx, p, api); e != nil {
		return nil, e
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
	var refused sandbox.Record
	if e = api.Create(ctx, old.Key, nodeSpec(), &refused); e == nil || !strings.Contains(e.Error(), "HTTP 410:") {
		return nil, errors.New("listener old key reused")
	}
	worker := &node{api: api}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	fresh, e := worker.create(ctx, key)
	if e != nil {
		return nil, e
	}
	if fresh.Ref == old.Ref {
		return nil, errors.New("listener old reference reused")
	}
	if e = syscallGuestBoundaryWithObserver(cfg, fresh.Ref, c.Process.Pid, false); e != nil {
		return nil, e
	}
	u, e := worker.execute(ctx, fresh.Ref, []string{"id", "-u"})
	if e != nil || strings.TrimSpace(u.Stdout) != "65534" {
		return nil, errors.New("listener fresh guest UID mismatch")
	}
	if mode == quotaLossRelease {
		boot, e := worker.execute(ctx, fresh.Ref, []string{"cat", "/proc/sys/kernel/random/boot_id"})
		if e != nil || strings.TrimSpace(boot.Stdout) == "" || strings.TrimSpace(boot.Stdout) == old.L2Boot {
			return nil, errors.New("listener old guest restored or boot missing")
		}
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
	if e = negativeQuotaClear(fs); e != nil {
		return nil, e
	}
	if e = p.stop(); e != nil {
		return nil, e
	}
	if e = os.Remove(mode.group()); e != nil {
		return nil, e
	}
	return map[string]any{"phase": mode.phase(), "l1_boot_changed": true, "exact_owner_bytes_policy_and_absent_namespace_before_daemon": true, "unexecuted_set_quota_state_checked_before_daemon": true, "cold_quota_record_empty": mode == quotaLossReserve, "old_durable_destroyed_resources_absent_key410": true, "fresh_real_kvm_uid_exec_destroy_uninstrumented_launch": true, "old_real_guest_boot_changed": mode == quotaLossRelease, "all_fixed_project_records_cleared": true, "owned_cgroup_root_removed": true, "listener_not_recreated_for_recovery": true}, nil
}
