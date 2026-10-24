//go:build linux && xandbox_host_fixture

package main

// TEST ONLY. A notification locates the ordinary quota commit, then CONTINUE
// enters the real syncfs kernel path on our suspended L1 mapper. D alone is
// insufficient: WAIT_KILLABLE_RECV can also sleep in D inside seccomp.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
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

const quotaBarrierPhase = "reserve-quota-syncfs-held"
const quotaBarrierReceiptPath = "/srv/fixture/quota-barrier-receipt.json"
const quotaBarrierGroup = "/sys/fs/cgroup/xandbox-sq-reserve-barrier-hang"

type quotaCommitMode uint8

const (
	quotaReserveHold quotaCommitMode = iota
	quotaReserveEIO
	quotaReleasePreHold
	quotaReleasePostHold
)

func (m quotaCommitMode) phase() string {
	switch m {
	case quotaReserveHold:
		return quotaBarrierPhase
	case quotaReserveEIO:
		return "reserve-quota-syncfs-real-eio"
	case quotaReleasePreHold:
		return "release-preclear-quota-syncfs-held"
	case quotaReleasePostHold:
		return "release-postclear-quota-syncfs-held"
	}
	return ""
}
func (m quotaCommitMode) release() bool { return m == quotaReleasePreHold || m == quotaReleasePostHold }
func (m quotaCommitMode) ordinal() int {
	switch m {
	case quotaReserveHold, quotaReserveEIO:
		return 1
	case quotaReleasePreHold:
		return 2
	case quotaReleasePostHold:
		return 3
	}
	return 0
}

type quotaBarrierPlan struct {
	Mode                  quotaCommitMode
	Key, Boot, ConfigHash string
	Dirty                 *os.File
}
type quotaBarrierReceipt struct {
	Mode                    quotaCommitMode `json:"mode,omitempty"`
	L2Boot                  string          `json:"l2_boot,omitempty"`
	Phase                   string
	Ref                     sandbox.Ref
	Key, L1Boot, ConfigHash string
	Owner                   []byte
}
type quotaBarrierLive struct {
	classes *prepareSampler
	p       *negativeDaemon
	o       *quotaNotifier
	plan    *quotaBarrierPlan
	done    chan error
	cancel  context.CancelFunc
}

func quotaOwnerSelector(q quotaNotif, project uint32) error {
	if q.Data.NR != int32(unix.SYS_QUOTACTL_FD) {
		return errors.New("owner selector requires quota syscall")
	}
	switch q.Data.Args[1] {
	case 0x80000702, 0x80000802:
		if q.Data.Args[2] != uint64(project) {
			return errors.New("quota selector does not match exact durable owner")
		}
	case 0x80000102, 0x80000402:
		if q.Data.Args[2] != 0 {
			return errors.New("global quota selector is not zero")
		}
	default:
		return errors.New("non-allowlisted owner quota command")
	}
	return nil
}
func decodeQuotaBarrierOwner(b []byte, ref sandbox.Ref) error {
	var o clearWindowOwner
	if e := strictjson.Decode(b, &o); e != nil {
		return e
	}
	if len(ref.ID) != 32 || len(ref.Generation) != 32 || strings.Trim(ref.ID+ref.Generation, "0123456789abcdef") != "" || o.Ref != ref || o.Version != 3 || !o.QuotaAttempted || o.InitializationAttempted || o.TemplateID != "" || o.UID != 480024 || o.ProjectID != quotaFirst {
		return errors.New("invalid fixed pre-fork barrier owner")
	}
	return nil
}
func quotaBarrierNamespaceAbsent(ref sandbox.Ref) error {
	for _, p := range []string{quotaBarrierGroup + "/" + ref.ID + ref.Generation, "/srv/sr/6/j/firecracker/" + ref.ID + ref.Generation} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return errors.New("pre-fork barrier has an execution namespace")
		}
	}
	return nil
}
func (o *quotaNotifier) prepareBarrier(q quotaNotif) error {
	if e := requireNode(); e != nil {
		return e
	}
	if o.barrier == nil || o.mapper == nil || o.state.name != quotaBarrierCase {
		return errors.New("fixed mapped barrier plan required")
	}
	if !o.barrier.Mode.release() && q.Data.NR == int32(unix.SYS_QUOTACTL_FD) && q.Data.Args[1] == 0x80000802 && !o.state.baselineSaved {
		ref, e := negativeLedgerRef(o.base, sandbox.Ref{})
		if e != nil {
			return e
		}
		b, e := privatefile.Read(o.base+"/s/firecracker/"+ref.ID+ref.Generation+".json", 2048)
		if e != nil {
			return e
		}
		if e = decodeQuotaBarrierOwner(b, ref); e != nil {
			return e
		}
		if e = quotaOwnerSelector(q, quotaFirst); e != nil {
			return e
		}
		if e = quotaBarrierNamespaceAbsent(ref); e != nil {
			return e
		}
		fs, e := openQuotaFSWithMapper(false, o.mapper)
		if e != nil {
			return e
		}
		r, e := fs.get(quotaFirst)
		fs.file.Close()
		if e != nil || !quotaEmpty(r) {
			return errors.New("pre-SET barrier baseline is not empty")
		}
		if _, e = os.Lstat(quotaBarrierReceiptPath); !os.IsNotExist(e) {
			return errors.New("refuse existing barrier receipt")
		}
		receipt := quotaBarrierReceipt{Mode: o.barrier.Mode, Phase: o.barrier.Mode.phase(), Ref: ref, Key: o.barrier.Key, L1Boot: o.barrier.Boot, ConfigHash: o.barrier.ConfigHash, Owner: b}
		// Persist BEFORE SET. No observer fsync/syncfs is issued after SET.
		if e = privateWrite(quotaBarrierReceiptPath, receipt); e != nil {
			return e
		}
		o.state.ref = ref
		o.state.owner = append([]byte(nil), b...)
		o.state.baselineSaved = true
	}
	if q.Data.NR != int32(unix.SYS_SYNCFS) || o.state.syncfsPassed+1 != o.barrier.Mode.ordinal() {
		return nil
	}
	if !o.state.baselineSaved || o.state.qsyncPassed != o.barrier.Mode.ordinal() || o.state.qsetPassed != expectedCommitSets(o.barrier.Mode) || o.state.barrierContinued {
		return errors.New("syncfs was not preceded by baseline, SET and Q_SYNC")
	}
	b, e := privatefile.Read(o.base+"/s/firecracker/"+o.state.ref.ID+o.state.ref.Generation+".json", 2048)
	if e != nil || !bytes.Equal(b, o.state.owner) {
		return errors.New("owner changed before quota filesystem barrier")
	}
	if e = quotaBarrierNamespaceAbsent(o.state.ref); e != nil {
		return e
	}
	fs, e := openQuotaFSWithMapper(false, o.mapper)
	if e != nil {
		return e
	}
	r, e := fs.get(quotaFirst)
	fs.file.Close()
	if e != nil {
		return e
	}
	if e = validateCommitBoundary(o.barrier.Mode, r); e != nil {
		return e
	}
	o.state.boundarySpace = r.Space
	o.state.boundaryInodes = r.Inodes
	// The already-created fixed project-zero file makes filesystem writeback
	// observable even if quota journal metadata became clean in the meantime.
	// This is a bounded TEST load, not a claim of per-project flush isolation.
	b = make([]byte, 4<<20)
	if n, e := o.barrier.Dirty.Write(b); e != nil || n != len(b) {
		return errors.New("fixed unsynced barrier write failed")
	}
	if o.barrier.Mode == quotaReserveEIO {
		var err error
		o.exitTrace, err = o.startExitTrace(q)
		if err != nil {
			return err
		}
		return o.mapper.setError()
	}
	return o.mapper.suspend() // NOFLUSH + SKIP_LOCKFS, own mapper only.
}

func barrierKernelStack(status, raw, stack string, fd uint64) bool {
	if !strings.Contains(status, "\nState:\tD (") || strings.Contains(stack, "seccomp") || !strings.Contains(stack, "syncfs") || !strings.Contains(stack, "sync_filesystem") {
		return false
	}
	f := strings.Fields(raw)
	if len(f) < 2 || f[0] != strconv.Itoa(unix.SYS_SYNCFS) {
		return false
	}
	got, e := strconv.ParseUint(f[1], 0, 64)
	return e == nil && got == fd
}
func (o *quotaNotifier) actualBarrierBlocked() (bool, error) {
	if e := requireNode(); e != nil {
		return false, e
	}
	s := o.snapshot()
	if s.err != nil {
		return false, s.err
	}
	if !s.barrierContinued {
		return false, nil
	}
	before, e := processStart(o.pid)
	if e != nil || before != o.identity {
		return false, errors.New("held daemon identity changed")
	}
	base := fmt.Sprintf("/proc/%d/task/%d", o.pid, s.barrierTID)
	status, e := os.ReadFile(base + "/status")
	if e != nil {
		return false, e
	}
	raw, e := os.ReadFile(base + "/syscall")
	if e != nil {
		return false, e
	}
	stack, e := os.ReadFile(base + "/stack")
	if e != nil {
		return false, e
	}
	after, e := processStart(o.pid)
	if e != nil || after != o.identity {
		return false, errors.New("held identity changed during proc observation")
	}
	return barrierKernelStack(string(status), string(raw), string(stack), s.barrierFD), nil
}
func fixedBarrierConfig() (firecracker.Config, error) {
	var cfg firecracker.Config
	b, e := privatefile.Read("/srv/sq/"+quotaBarrierCase+"/backend.json", 8192)
	if e != nil {
		return cfg, e
	}
	if e = strictjson.Decode(b, &cfg); e != nil {
		return cfg, e
	}
	if cfg.RuntimeRoot != "/srv/sr/6" || cfg.CgroupRoot != quotaBarrierGroup || cfg.UIDStart != 480024 || cfg.UIDCount != 3 || cfg.Version != 1 || cfg.Snapshot != nil || cfg.Quota == nil || cfg.Quota.ProjectStart != quotaFirst || cfg.Quota.MaxBytes != 192<<20 || cfg.Quota.MaxInodes != 128 {
		return cfg, errors.New("fixed barrier policy changed")
	}
	return cfg, nil
}
func (n *node) quotaBarrierCheckpoint(ctx context.Context) (map[string]any, error) {
	return n.quotaBarrierCheckpointOn(ctx, quotaReserveHold)
}
func (n *node) quotaBarrierCheckpointOn(ctx context.Context, mode quotaCommitMode) (result map[string]any, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if mode.phase() == "" || !n.quotaStateIO || n.mapper == nil || n.process != nil || n.quotaHeld != nil {
		return nil, errors.New("fresh mapped quota node required")
	}
	for _, p := range []string{"/srv/sq", "/srv/sr", quotaBarrierReceiptPath} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return nil, errors.New("refuse existing barrier scope")
		}
	}
	base, _ := quotaSyscallBase(quotaBarrierCase)
	for _, p := range []string{"/srv/sq", base, base + "/s", "/srv/sr", quotaBarrierGroup} {
		if e := os.Mkdir(p, 0700); e != nil {
			return nil, e
		}
	}
	if e := os.WriteFile(quotaBarrierGroup+"/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); e != nil {
		return nil, e
	}
	b, e := os.ReadFile("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	var cfg firecracker.Config
	if e = strictjson.Decode(b, &cfg); e != nil {
		return nil, e
	}
	if cfg.Quota == nil || cfg.Version != 1 || cfg.Snapshot != nil {
		return nil, errors.New("fixed cold quota seed required")
	}
	cfg.RuntimeRoot = "/srv/sr/6"
	cfg.CgroupRoot = quotaBarrierGroup
	cfg.UIDStart = 480024
	cfg.UIDCount = 3
	cfg.Quota.ProjectStart = quotaFirst
	if e = privateWrite(base+"/backend.json", cfg); e != nil {
		return nil, e
	}
	h, e := fileHash(base + "/backend.json")
	if e != nil {
		return nil, e
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	dirty, e := os.OpenFile("/srv/fixture/quota-barrier-dirty", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	if e = dirty.Sync(); e != nil {
		dirty.Close()
		return nil, e
	}
	a, e := quotaAttributes("/srv/fixture/quota-barrier-dirty", nil)
	if e != nil || a.Project != 0 || a.XFlags&quotaInherit != 0 {
		dirty.Close()
		return nil, errors.New("dirty probe must remain project zero")
	}
	plan := &quotaBarrierPlan{Mode: mode, Key: key, Boot: n.boot, ConfigHash: h, Dirty: dirty}
	liveCtx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	p, o, e := startQuotaNotifiedOn(liveCtx, quotaBarrierCase, cfg.RuntimeRoot, n.mapper, plan)
	if e != nil {
		cancel()
		dirty.Close()
		return nil, e
	}
	live := &quotaBarrierLive{p: p, o: o, plan: plan, done: make(chan error, 1), cancel: cancel}
	api := client.NewWithToken(base+"/s/api.sock", n.token)
	defer func() {
		if err != nil {
			_ = n.mapper.linear()
			cancel()
			_ = p.stop()
			_ = o.close()
			api.Close()
			dirty.Close()
		}
	}()
	if e = negativeReady(ctx, p, api); e != nil {
		return nil, e
	}
	if mode == quotaReserveEIO {
		live.classes, e = startPrepareSampler(liveCtx, base+"/s/metrics.sock")
		if e != nil {
			return nil, e
		}
		defer func() {
			if live.classes != nil {
				live.classes.close()
				live.classes = nil
			}
		}()
		v, e := live.classes.snapshot()
		if e != nil || v != (prepareClasses{}) {
			return nil, errors.New("pre-fault producer counters not zero")
		}
	}
	if mode.release() {
		return n.releaseCommitCheckpoint(ctx, mode, live, api, cfg)
	}
	o.arm()
	go func() { var r sandbox.Record; live.done <- api.Create(liveCtx, key, nodeSpec(), &r) }()
	if mode == quotaReserveEIO {
		return n.reserveCommitEIO(ctx, live, api)
	}
	if e = waitNode(ctx, func() (bool, error) {
		select {
		case e := <-live.done:
			if e == nil {
				return false, errors.New("ordinary Prepare completed without quota syncfs barrier")
			}
			return false, e
		default:
		}
		return o.actualBarrierBlocked()
	}); e != nil {
		return nil, e
	}
	for i := 0; i < 3; i++ {
		time.Sleep(100 * time.Millisecond)
		blocked, e := o.actualBarrierBlocked()
		if e != nil || !blocked {
			return nil, errors.New("actual syncfs was not continuously held in filesystem kernel path")
		}
	}
	s := o.snapshot()
	var old sandbox.Record
	if e = api.Do(ctx, "GET", nodePath(s.ref), nil, &old); e != nil {
		return nil, e
	}
	if old.State != sandbox.Creating || !old.StoppedAt.IsZero() || !old.DestroyedAt.IsZero() {
		return nil, errors.New("held pre-fork Prepare changed lifecycle state")
	}
	other, e := randomKey()
	if e != nil {
		return nil, e
	}
	request, cancelRequest := context.WithTimeout(ctx, 2*time.Second)
	defer cancelRequest()
	var refused sandbox.Record
	if e = api.Create(request, other, nodeSpec(), &refused); e == nil || !strings.Contains(e.Error(), "HTTP 503:") {
		return nil, errors.New("held quota commit returned capacity")
	}
	select {
	case <-live.done:
		return nil, errors.New("held Create returned before power cut")
	default:
	}
	// Retain controller, notifier, dirty FD and request until outer L1 death.
	// No /srv read/write, quota query or sync is performed while suspended.
	n.quotaHeld = live
	return map[string]any{"phase": quotaBarrierPhase, "checkpoint_receipt_fsynced_before_set": true, "pre_fork_namespace_absent_before_suspend": true, "durable_attempted_owner_before_set": true, "installed_limits_checked_before_suspend": true, "ordinary_qsync_returned_before_syncfs": true, "notification_continued_into_real_kernel": true, "actual_syncfs_syscall_D_filesystem_stack_not_seccomp": true, "actual_kernel_hold_rechecked_three_times": true, "fixed_project_zero_dirty_bytes": 4 << 20, "no_create_ack_while_commit_held": true, "capacity_retained_new_create503": true, "no_quota_or_srv_reads_after_suspend": true, "mapper_still_suspended_until_power_cut": true, "no_l2_vm_born_at_checkpoint": true}, nil
}

func runQuotaBarrierRecoveryDaemon() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedBarrierConfig(); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	base, _ := quotaSyscallBase(quotaBarrierCase)
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", base + "/s", "-auth-file", "/srv/config/auth.json", "-firecracker-config", base + "/backend.json", "-max-instances", "1", "-metrics"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}
func (n *node) recoverQuotaBarrier(ctx context.Context) (map[string]any, error) {
	return n.recoverQuotaBarrierOn(ctx, quotaReserveHold)
}
func (n *node) recoverQuotaBarrierOn(ctx context.Context, mode quotaCommitMode) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if mode.phase() == "" || !n.quotaStateIO || n.mapper == nil || n.process != nil || n.quotaHeld != nil {
		return nil, errors.New("fresh mapped recovery boot required")
	}
	b, e := privatefile.Read(quotaBarrierReceiptPath, 8192)
	if e != nil {
		return nil, e
	}
	var old quotaBarrierReceipt
	if e = strictjson.Decode(b, &old); e != nil {
		return nil, e
	}
	if old.Mode != mode || old.Phase != mode.phase() || old.L1Boot == "" || old.L1Boot == n.boot || len(old.Key) != 64 || strings.Trim(old.Key, "0123456789abcdef") != "" {
		return nil, errors.New("invalid cold pre-fork barrier receipt")
	}
	if e = decodeQuotaBarrierOwner(old.Owner, old.Ref); e != nil {
		return nil, e
	}
	cfg, e := fixedBarrierConfig()
	if e != nil {
		return nil, e
	}
	base, _ := quotaSyscallBase(quotaBarrierCase)
	h, e := fileHash(base + "/backend.json")
	if e != nil || h != old.ConfigHash {
		return nil, errors.New("barrier immutable policy changed across cold boot")
	}
	b, e = privatefile.Read(base+"/s/firecracker/"+old.Ref.ID+old.Ref.Generation+".json", 2048)
	if e != nil || !bytes.Equal(b, old.Owner) {
		return nil, errors.New("durable attempted owner lost across commit crash")
	}
	if e = quotaBarrierNamespaceAbsent(old.Ref); e != nil {
		return nil, e
	}
	q, e := openQuotaFSWithMapper(false, n.mapper)
	if e != nil {
		return nil, e
	}
	defer q.file.Close()
	r, e := q.get(quotaFirst)
	if e != nil {
		return nil, e
	}
	empty := quotaEmpty(r)
	if !empty && (r.BHard != 192<<10 || r.IHard != 128 || r.BSoft|r.ISoft|r.Space|r.Inodes|r.BTime|r.ITime != 0) {
		return nil, errors.New("unreturned commit recovered inconsistent policy or usage")
	}
	for id := quotaFirst + 1; id < quotaFirst+3; id++ {
		v, e := q.get(id)
		if e != nil || !quotaEmpty(v) {
			return nil, errors.New("unrelated fixed quota record changed")
		}
	}
	if e = os.Mkdir(quotaBarrierGroup, 0700); e != nil {
		return nil, e
	}
	if e = os.WriteFile(quotaBarrierGroup+"/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); e != nil {
		return nil, e
	}
	log, e := os.OpenFile("/srv/fixture/quota-barrier-cold.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	c := exec.CommandContext(ctx, "/usr/bin/xandbox-host-fixture", "-mode", "quota-barrier-recover-daemon")
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
		var v sandbox.Record
		e := api.Do(ctx, "GET", nodePath(old.Ref), nil, &v)
		return e == nil && v.State == sandbox.Destroyed, e
	}); e != nil {
		return nil, e
	}
	if e = negativeNoResources(cfg, base, old.Ref); e != nil {
		return nil, e
	}
	var replay sandbox.Record
	if e = api.Create(ctx, old.Key, nodeSpec(), &replay); e == nil || !strings.Contains(e.Error(), "HTTP 410:") {
		return nil, errors.New("in-flight crashed key reused")
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
		return nil, errors.New("old reference reused after commit crash")
	}
	if e = syscallGuestBoundaryWithObserver(cfg, fresh.Ref, c.Process.Pid, false); e != nil {
		return nil, e
	}
	u, e := worker.execute(ctx, fresh.Ref, []string{"id", "-u"})
	if e != nil || strings.TrimSpace(u.Stdout) != "65534" {
		return nil, errors.New("fresh recovered guest UID mismatch")
	}
	if mode.release() {
		boot, e := worker.execute(ctx, fresh.Ref, []string{"cat", "/proc/sys/kernel/random/boot_id"})
		if e != nil || strings.TrimSpace(boot.Stdout) == "" || strings.TrimSpace(boot.Stdout) == old.L2Boot || old.L2Boot == "" {
			return nil, errors.New("old release guest restored or boot missing")
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
	if e = negativeQuotaClear(q); e != nil {
		return nil, e
	}
	if e = p.stop(); e != nil {
		return nil, e
	}
	if e = os.Remove(quotaBarrierGroup); e != nil {
		return nil, e
	}
	return map[string]any{"phase": mode.phase(), "old_real_guest_boot_changed": mode.release(), "l1_boot_changed": true, "attempted_owner_bytes_policy_and_absent_namespace_before_daemon": true, "unreturned_commit_empty_or_known_limits_checked": true, "cold_quota_record_empty": empty, "no_assigned_guest_restore": true, "old_durable_destroyed": true, "old_resources_absent": true, "old_key_refused410": true, "fresh_real_kvm_uid_exec_destroy_uninstrumented_launch": true, "all_fixed_project_records_cleared": true, "owned_cgroup_root_removed": true}, nil
}
