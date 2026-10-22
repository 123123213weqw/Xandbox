//go:build linux

package session

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type kvmSessionFixture struct {
	StateDir       string `json:"state_dir"`
	ConfigPath     string `json:"config_path"`
	ReportPath     string `json:"report_path"`
	SourceRevision string `json:"source_revision"`
}
type dualBarrier struct {
	Store
	prepared, committing           chan Record
	releasePrepared, releaseCommit chan struct{}
	oncePrepared, onceCommit       sync.Once
}

func (s *dualBarrier) Save(r Record) error {
	if r.State == Prepared && r.Revision == 1 {
		s.oncePrepared.Do(func() { s.prepared <- clone(r); <-s.releasePrepared })
	}
	if r.State == Active && r.Revision == 2 {
		s.onceCommit.Do(func() { s.committing <- clone(r); <-s.releaseCommit })
	}
	return s.Store.Save(r)
}

func TestKVMSessionCommitIOIsolation(t *testing.T) {
	if os.Getenv("XANDBOX_KVM_SESSION_ACCEPTANCE") != "1" {
		t.Skip("requires explicit private root KVM fixture; skip is not runtime acceptance")
	}
	if os.Geteuid() != 0 || runtime.Version() != "go1.27.3" {
		t.Fatal("acceptance requires root and patched Go1.27.3 binary")
	}
	raw, e := privatefile.Read(os.Getenv("XANDBOX_KVM_SESSION_FIXTURE"), 16384)
	if e != nil {
		t.Fatal(e)
	}
	var fixture kvmSessionFixture
	if e = strictjson.Decode(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	if !filepath.IsAbs(fixture.StateDir) || !filepath.IsAbs(fixture.ConfigPath) || !filepath.IsAbs(fixture.ReportPath) || len(fixture.SourceRevision) != 40 {
		t.Fatal("invalid fixture")
	}
	state, e := privatefile.EnsureDirectory(fixture.StateDir)
	if e != nil {
		t.Fatal(e)
	}
	lock, e := os.OpenFile(filepath.Join(state, "controller.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	store, e := sandbox.NewFileStore(filepath.Join(state, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	rows, e := store.Load()
	if e != nil || len(rows) != 0 {
		t.Fatal("requires fresh ledger", e)
	}
	driver, e := firecracker.New(state, fixture.ConfigPath, rows)
	if e != nil {
		t.Fatal(e)
	}
	opts := sandbox.Options{MaxInstances: 2, StopWorkers: 1, CleanupWorkers: 1, WorkQueueSize: 1, ReapInterval: 10 * time.Millisecond, PrepareTimeout: 30 * time.Second, StopTimeout: 5 * time.Second, CleanupTimeout: 10 * time.Second}
	core, e := sandbox.NewManager(store, driver, opts)
	if e != nil {
		t.Fatal(e)
	}
	sessionStore, e := NewFileStore(filepath.Join(state, "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	barrier := &dualBarrier{Store: sessionStore, prepared: make(chan Record, 1), committing: make(chan Record, 1), releasePrepared: make(chan struct{}), releaseCommit: make(chan struct{})}
	b, e := New(core, barrier, Options{})
	if e != nil {
		t.Fatal(e)
	}
	var pOnce, cOnce sync.Once
	releaseP := func() { pOnce.Do(func() { close(barrier.releasePrepared) }) }
	releaseC := func() { cOnce.Do(func() { close(barrier.releaseCommit) }) }
	defer func() {
		releaseP()
		releaseC()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if e := b.Close(ctx); e != nil {
			t.Error(e)
		}
		if e := core.Close(ctx); e != nil {
			t.Error(e)
		}
	}()
	policyRaw, e := privatefile.Read(fixture.ConfigPath, 16384)
	if e != nil {
		t.Fatal(e)
	}
	var policy firecracker.Config
	if e = strictjson.Decode(policyRaw, &policy); e != nil {
		t.Fatal(e)
	}
	group := func(ref sandbox.Ref) string { return filepath.Join(policy.CgroupRoot, ref.ID+ref.Generation) }
	empty := func(ref sandbox.Ref) bool {
		data, e := os.ReadFile(filepath.Join(group(ref), "cgroup.events"))
		return os.IsNotExist(e) || (e == nil && strings.Contains(string(data), "populated 0"))
	}
	wait := func(label string, p func() bool) {
		t.Helper()
		end := time.Now().Add(10 * time.Second)
		for time.Now().Before(end) {
			if p() {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("not reached: " + label)
	}
	owner := sandbox.Owner{TenantID: "session-proof", MaxInstances: 2}
	request := sandbox.CreateRequest{TTLMS: 60000, Limits: sandbox.Limits{MaxExecMS: 60000}}
	first, e := b.Open(context.Background(), owner, "create", request)
	if e != nil {
		t.Fatal(e)
	}
	if core.Stats().Backend != "firecracker" || empty(first.Current) {
		t.Fatal("not an actual live Firecracker generation")
	}
	execute := func(binding Result, argv []string) sandbox.Job {
		t.Helper()
		job, e := b.Exec(owner.TenantID, binding.ID, binding.Revision, sandbox.ExecRequest{Argv: argv, TimeoutMS: 5000})
		if e != nil {
			t.Fatal(e)
		}
		vmID, jobID := job.Ref.ID, job.ID
		wait("guest result", func() bool {
			var e error
			job, e = core.GetJobScoped(owner.TenantID, vmID, jobID)
			return e == nil && job.Status != "RUNNING"
		})
		return job
	}
	if job := execute(first, []string{"id", "-u"}); job.Status != "EXITED" || strings.TrimSpace(job.Output.Stdout) != "65534" {
		t.Fatal("guest UID assertion failed")
	}
	if _, e = core.ExecScoped(owner.TenantID, first.Current.ID, sandbox.ExecRequest{Generation: first.Current.Generation, Argv: []string{"true"}}); !errors.Is(e, sandbox.ErrNotReady) {
		t.Fatal("plain Exec bypassed managed capability", e)
	}
	if _, e = b.Exec(owner.TenantID, first.ID, 1, sandbox.ExecRequest{Argv: []string{"sh", "-c", "echo started > active; sleep 50"}, TimeoutMS: 60000}); e != nil {
		t.Fatal(e)
	}
	wait("old guest started", func() bool { return execute(first, []string{"test", "-e", "active"}).Output.ExitCode == 0 })
	switched := make(chan error, 1)
	go func() {
		_, e := b.Switch(context.Background(), owner, first.ID, "switch", SwitchRequest{ExpectedRevision: 1, Create: request})
		switched <- e
	}()
	var prepared Record
	select {
	case prepared = <-barrier.prepared:
	case <-time.After(35 * time.Second):
		t.Fatal("prepared barrier not reached")
	}
	candidate := prepared.Attempts[len(prepared.Attempts)-1].Target
	if empty(first.Current) || empty(candidate) || core.Stats().Active != 2 {
		t.Fatal("candidate preparation did not retain two real live VMs")
	}
	if job := execute(first, []string{"echo", "old-usable-during-prepare"}); job.Status != "EXITED" {
		t.Fatal("candidate journal blocked old route")
	}
	if _, e = core.ExecScoped(owner.TenantID, candidate.ID, sandbox.ExecRequest{Generation: candidate.Generation, Argv: []string{"true"}}); !errors.Is(e, sandbox.ErrNotReady) {
		t.Fatal("unpublished candidate became executable", e)
	}
	releaseP()
	select {
	case <-barrier.committing:
	case <-time.After(10 * time.Second):
		t.Fatal("commit barrier not reached")
	}
	began := time.Now()
	wait("old host cgroup stopped independently of session fsync", func() bool { return empty(first.Current) })
	oldStopMS := float64(time.Since(began)) / float64(time.Millisecond)
	if _, e = b.Exec(owner.TenantID, first.ID, 1, sandbox.ExecRequest{Argv: []string{"true"}}); !errors.Is(e, ErrBusy) {
		t.Fatal("old route not revoked during blocked commit", e)
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	e = b.Close(closeCtx)
	cancel()
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("blocked journal reported a finished Close", e)
	}
	wait("candidate host cgroup stopped despite blocked binding journal", func() bool { return empty(candidate) })
	drain, cancelDrain := context.WithTimeout(context.Background(), 10*time.Second)
	if e = core.Close(drain); e != nil {
		cancelDrain()
		t.Fatal(e)
	}
	cancelDrain()
	// A failed Close never releases exclusive state authority while its writer
	// is alive. This is the embedding equivalent of sandboxd's retained lock.
	second, e := os.OpenFile(filepath.Join(state, "controller.lock"), os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	e = unix.Flock(int(second.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	second.Close()
	if e == nil {
		t.Fatal("second controller acquired live writer's state")
	}
	releaseC()
	select {
	case e = <-switched:
		if e == nil {
			t.Fatal("late fsync returned usable binding")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("switch did not quiesce")
	}
	finish, cancelFinish := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFinish()
	if e = b.Close(finish); e != nil {
		t.Fatal(e)
	}
	saved, has, e := b.Get(owner.TenantID, first.ID)
	if e != nil || has || saved.State != Closed {
		t.Fatal("closed route resurrected", e)
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_UN); e != nil {
		t.Fatal(e)
	}
	nextLock, e := os.OpenFile(filepath.Join(state, "controller.lock"), os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer nextLock.Close()
	if e = unix.Flock(int(nextLock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	rows, e = store.Load()
	if e != nil {
		t.Fatal(e)
	}
	nextDriver, e := firecracker.New(state, fixture.ConfigPath, rows)
	if e != nil {
		t.Fatal(e)
	}
	nextCore, e := sandbox.NewManager(store, nextDriver, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer nextCore.Close(finish)
	next, e := New(nextCore, sessionStore, Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close(finish)
	_, has, e = next.Get(owner.TenantID, first.ID)
	if e != nil || has || nextCore.Stats().Active != 0 {
		t.Fatal("recovery revived session/VM", e)
	}
	report := map[string]any{"test": "real_kvm_session_commit_fsync_stall", "production_ready": false, "source_revision": fixture.SourceRevision, "toolchain": runtime.Version(), "fault_model": "test-only blocked session binding Save; not an actual broken disk or production RPC/flag", "commit_barrier_to_old_stopped_observed_ms": oldStopMS, "stop_workers": 1, "cleanup_workers": 1, "queue_capacity_per_pool": 1, "checks": []string{
		"actual real-driver guest UID and managed capability enforcement",
		"two real KVM generations live after candidate READY while old session remains executable",
		"unpublished candidate rejects plain per-VM execution",
		"old host execution stops while final session binding fsync is blocked",
		"Close deadline does not claim journal writer termination",
		"candidate host execution stops independently of blocked binding journal",
		"exclusive state lock retained until old writer and mutations quiesce",
		"late fsync never republishes a closed session binding",
		"fresh controller/driver/broker recovers all owned resources without reviving sessions",
	}}
	data, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(fixture.ReportPath, append(data, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}
