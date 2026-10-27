//go:build linux

package firecracker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/guestbridge"
	"github.com/123123213weqw/Xandbox/internal/guestinit"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/hostclock"
	"github.com/123123213weqw/Xandbox/internal/lease"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/telemetry"
	"golang.org/x/sys/unix"
)

type process struct {
	leaseMu            sync.Mutex
	leaseFD            int
	leaseClosed        bool
	binding            lease.Binding
	hardDeadline       int64
	nextRenew          int64
	sequence           uint64
	life               *os.File // Only the controller owns a write end; never inherited by VMM.
	done               chan struct{}
	bootID             string
	initializationHash string
	slots              chan struct{} // Match the guest executor's two simultaneous groups.
}

type driver struct {
	mu       sync.Mutex // Never held across VM RPCs, process waits or disk cleanup.
	registry *registry
	cfg      Config
	procs    map[string]*process
	quota    *projectQuota
	node     *nodeEnvelope
}

// New requires root and a pre-delegated empty cgroup-v2 root. Its caller must
// hold the exclusive state lock throughout the driver's lifetime.
func New(stateDir, configPath string, records []sandbox.Record) (sandbox.Driver, error) {
	return newDriver(stateDir, configPath, records, nil)
}
func NewWithAdmission(stateDir, configPath string, records []sandbox.Record, limits sandbox.AdmissionLimits) (sandbox.Driver, error) {
	return newDriver(stateDir, configPath, records, &limits)
}
func newDriver(stateDir, configPath string, records []sandbox.Record, limits *sandbox.AdmissionLimits) (sandbox.Driver, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("Firecracker driver requires privileged Linux controller")
	}
	if err := securePath(stateDir); err != nil {
		return nil, err
	}
	if err := securePath(configPath); err != nil {
		return nil, err
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if cfg.Node != nil {
		if limits == nil {
			return nil, errors.New("version3 requires complete bound admission limits")
		}
		if err = cfg.Node.match(*limits, true); err != nil {
			return nil, err
		}
		allocated := 0
		for _, r := range records {
			if r.State != sandbox.Destroyed {
				allocated++
			}
		}
		if err = cfg.Node.match(sandbox.AdmissionLimits{RetainedRecords: len(records), AllocatedInstances: allocated}, false); err != nil {
			return nil, err
		}
	}
	for _, asset := range cfg.assets() {
		if err := checkAsset(asset); err != nil {
			return nil, err
		}
	}
	for _, executable := range []Asset{cfg.Firecracker, cfg.Jailer, cfg.Warden} {
		info, err := os.Stat(executable.Path)
		if err != nil || info.Mode().Perm()&0111 == 0 {
			return nil, errors.New("trusted executable is not executable")
		}
	}
	info, err := os.Stat(cfg.Workspace.Path)
	if err != nil || info.Size() != diskBytes {
		return nil, errors.New("workspace template must be a pinned private-copy 128 MiB ext4 image")
	}
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	api, err := unix.IoctlRetInt(int(kvm.Fd()), 0xae00)
	kvm.Close()
	if err != nil || api != 12 {
		return nil, errors.New("KVM API unavailable")
	}
	if err := securePath(cfg.CgroupRoot); err != nil {
		return nil, err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(cfg.CgroupRoot, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("cgroup root is not a cgroup-v2 mount")
	}
	procs, err := os.ReadFile(filepath.Join(cfg.CgroupRoot, "cgroup.procs"))
	if err != nil || len(strings.TrimSpace(string(procs))) != 0 {
		return nil, errors.New("delegated cgroup root must contain no processes")
	}
	controllers, err := os.ReadFile(filepath.Join(cfg.CgroupRoot, "cgroup.subtree_control"))
	if err != nil || !hasWords(string(controllers), "memory", "pids", "cpu") {
		return nil, errors.New("operator must delegate memory, pids and cpu controllers")
	}
	if cfg.IO != nil && !hasWords(string(controllers), "io") {
		return nil, ErrIODelegation
	}
	if err := privateDir(cfg.RuntimeRoot); err != nil {
		return nil, err
	}
	if err := unix.Statfs(cfg.RuntimeRoot, &fs); err != nil || fs.Flags&unix.ST_NOEXEC != 0 {
		return nil, errors.New("runtime filesystem must permit jailer/VMM execution; do not disable host noexec as a fallback")
	}
	if cfg.IO != nil {
		if err := checkRuntimeIO(cfg.RuntimeRoot, *cfg.IO); err != nil {
			return nil, err
		}
	}
	node, err := openNodeEnvelope(cfg, stateDir)
	if err != nil {
		return nil, err
	}
	keepNode := false
	defer func() {
		if node != nil && !keepNode {
			node.close()
		}
	}()
	quota, err := openProjectQuota(cfg)
	if err != nil {
		return nil, err
	}
	keepQuota := false
	defer func() {
		if quota != nil && !keepQuota {
			quota.anchor.Close()
		}
	}()
	for _, p := range []string{filepath.Join(cfg.RuntimeRoot, "j"), filepath.Join(cfg.RuntimeRoot, "j/firecracker"), filepath.Join(stateDir, "firecracker")} {
		if err := privateDir(p); err != nil {
			return nil, err
		}
	}
	r, err := newRegistry(filepath.Join(stateDir, "firecracker"), cfg, records)
	if err != nil {
		return nil, err
	}
	if quota != nil {
		if err := quota.reconcile(r.owners); err != nil {
			return nil, err
		}
		r.beforeRelease = quota.release
	}
	// Unknown resources must not be adopted or silently ignored. In particular,
	// a lost ownership manifest must not make a previous VM appear destroyed.
	for _, parent := range []string{cfg.CgroupRoot, filepath.Join(cfg.RuntimeRoot, "j/firecracker")} {
		entries, err := os.ReadDir(parent)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			isJailRoot := parent != cfg.CgroupRoot
			if (isJailRoot && !e.IsDir()) || ((isJailRoot || e.IsDir()) && !validOwnership(r.owners[e.Name()], cfg)) {
				return nil, errors.New("unowned backend resources require operator reconciliation")
			}
		}
	}
	if cfg.Snapshot != nil {
		r.hostABI, err = SnapshotHostABI()
		if err != nil {
			return nil, err
		}
		a, e := os.Stat(cfg.RuntimeRoot)
		if e != nil {
			return nil, e
		}
		b, e := os.Stat(r.catalog.root)
		if e != nil {
			return nil, e
		}
		sa, oka := a.Sys().(*syscall.Stat_t)
		sb, okb := b.Sys().(*syscall.Stat_t)
		if !oka || !okb || sa.Dev != sb.Dev {
			return nil, errors.New("snapshot catalog and runtime require the same filesystem")
		}
	}
	keepQuota = true
	keepNode = true
	return &driver{registry: r, cfg: cfg, procs: make(map[string]*process), quota: quota, node: node}, nil
}

func (*driver) Name() string { return "firecracker" }

func (d *driver) paths(k string) (string, string) {
	return filepath.Join(d.cfg.CgroupRoot, k), filepath.Join(d.cfg.RuntimeRoot, "j/firecracker", k)
}

func (d *driver) Prepare(ctx context.Context, ref sandbox.Ref, spec sandbox.Preparation) (retErr error) {
	defer func() {
		if retErr != nil {
			// Only a sealed class leaves the backend. Neither the log handler nor
			// its queue receives or formats the original error object.
			slog.Error("Firecracker preparation failed", diagnostics.ReasonAttribute, int(DiagnosticReason(retErr)))
		}
	}()
	k, err := key(ref)
	if err != nil {
		return err
	}
	nowNS, clockErr := hostclock.NowNS()
	if clockErr != nil || !lease.ValidLifetime(nowNS, spec.DeadlineNS) {
		return errors.New("invalid or expired host lifetime")
	}
	if d.cfg.IO != nil {
		if err := checkRuntimeIO(d.cfg.RuntimeRoot, *d.cfg.IO); err != nil {
			return err
		}
	}
	if d.node != nil {
		slotSpan := telemetry.StartCreation(ctx, telemetry.DriverPrepareSlot)
		slotErr := d.node.acquirePrepare(ctx)
		slotSpan.End()
		if slotErr != nil {
			return slotErr
		}
		defer d.node.preparing.release()
	}
	group, jail := d.paths(k)
	for _, p := range []string{group, jail} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			return errors.New("generation resource already exists")
		}
	}
	ownershipSpan := telemetry.StartCreation(ctx, telemetry.DriverOwnership)
	owner, err := d.registry.reserveContext(ctx, ref)
	ownershipSpan.End()
	if err != nil {
		return err
	}
	if d.quota != nil {
		quotaSpan := telemetry.StartCreation(ctx, telemetry.DriverQuotaReserve)
		quotaErr := d.quota.reserve(owner, func() error { return d.registry.markQuotaAttempt(k) })
		quotaSpan.End()
		if quotaErr != nil {
			return quotaErr
		}
	}
	// A configured reserved range is mandatory; also reject known host accounts.
	if _, err := user.LookupId(strconv.Itoa(owner.UID)); err == nil {
		return errors.New("reserved UID conflicts with a host account")
	} else {
		var unknown user.UnknownUserIdError
		if !errors.As(err, &unknown) {
			return errors.New("unable to verify reserved UID")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Mkdir(group, 0700); err != nil {
		return err
	}
	for file, value := range map[string]string{
		"memory.max": strconv.FormatUint(instanceMemoryMax, 10), "memory.swap.max": "0", "memory.oom.group": "1",
		"pids.max": strconv.FormatUint(instancePidsMax, 10), "cpu.max": fmt.Sprintf("%d %d", instanceCPUQuota, nodeCPUPeriod),
	} {
		if err := os.WriteFile(filepath.Join(group, file), []byte(value), 0); err != nil {
			return err
		}
		actual, err := os.ReadFile(filepath.Join(group, file))
		if err != nil || strings.TrimSpace(string(actual)) != value {
			return errors.New("host resource limit verification failed")
		}
	}
	if d.cfg.IO != nil {
		if err := applyKernelIO(group, *d.cfg.IO); err != nil {
			return err
		}
	}
	cg, err := os.Open(group)
	if err != nil {
		return err
	}
	defer cg.Close()
	root := filepath.Join(jail, "root")
	if d.quota != nil {
		if err := os.Mkdir(jail, 0700); err != nil {
			return err
		}
		if err := d.quota.setDir(jail, owner, true); err != nil {
			return err
		}
		if err := os.Mkdir(root, 0700); err != nil {
			return err
		}
		if err := d.quota.setDir(root, owner, true); err != nil {
			return err
		}
	} else if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	assets := map[string]Asset{"workspace.ext4": d.cfg.Workspace}
	if d.cfg.Snapshot == nil {
		assets["kernel"] = d.cfg.Kernel
		assets["initrd"] = d.cfg.Initrd
	}
	copySpan := telemetry.StartCreation(ctx, telemetry.DriverAssetCopy)
	defer copySpan.End()
	for name, asset := range assets {
		if err := copyAsset(ctx, asset, filepath.Join(root, name)); err != nil {
			return err
		}
	}
	copySpan.End()
	if d.registry.catalog != nil {
		// Only trusted immutable links enter during this pre-fork window.
		// Every failure leaves an owned, never-admitted jail for normal GC.
		if d.quota != nil {
			if err := d.quota.setDir(root, owner, false); err != nil {
				return err
			}
		}
		if err := d.registry.catalog.linkOwned(ctx, owner, root); err != nil {
			return err
		}
		if d.quota != nil {
			if err := d.quota.setDir(root, owner, true); err != nil {
				return err
			}
		}
	}
	if err := os.Chmod(filepath.Join(root, "workspace.ext4"), 0600); err != nil {
		return err
	}
	if err := os.Chown(filepath.Join(root, "workspace.ext4"), owner.UID, owner.UID); err != nil {
		return err
	}
	if d.quota != nil {
		quotaSpan := telemetry.StartCreation(ctx, telemetry.DriverQuotaVerify)
		quotaErr := d.quota.verifyPrepared(jail, owner)
		quotaSpan.End()
		if quotaErr != nil {
			return quotaErr
		}
	}
	activationSpan := telemetry.StartCreation(ctx, telemetry.DriverActivation)
	defer activationSpan.End()
	leaseRead, leaseWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer leaseRead.Close()
	keepLease := false
	defer func() {
		if !keepLease {
			leaseWrite.Close()
		}
	}()
	kill, err := os.OpenFile(filepath.Join(group, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer kill.Close()
	// The first fork is already in the generation cgroup and new network
	// namespace. The jailer inherits both, then enters that exact existing group.
	rel := strings.TrimPrefix(group, "/sys/fs/cgroup/")
	args := []string{"-cgroup", rel, "-hard-deadline-ns", strconv.FormatInt(spec.DeadlineNS, 10), "--", d.cfg.Jailer.Path, "--id", k, "--exec-file", d.cfg.Firecracker.Path,
		"--uid", strconv.Itoa(owner.UID), "--gid", strconv.Itoa(owner.UID), "--chroot-base-dir", filepath.Join(d.cfg.RuntimeRoot, "j"),
		"--cgroup-version", "2", "--parent-cgroup", rel, "--resource-limit", "no-file=256", "--resource-limit", "fsize=134217728",
		"--", "--api-sock", "/api.sock"}
	if d.quota != nil {
		args = append([]string{"-deny-quota-mutation"}, args...)
	}
	cmd := exec.Command(d.cfg.Warden.Path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.ExtraFiles = []*os.File{leaseRead, kill}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd()), Cloneflags: unix.CLONE_NEWNET, Setsid: true}
	diagnostic := &startupDiagnostic{}
	defer diagnostic.disable()
	cmd.Stderr = diagnostic
	// No task console is retained: bounded initialization stderr is disabled and
	// cleared before READY, stdout is always discarded. API hides raw failures.
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := newProcess(leaseWrite, k, spec.DeadlineNS)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start owned warden (clone3 required; no fallback): %w", err)
	}
	d.mu.Lock()
	d.procs[k] = p
	d.mu.Unlock()
	keepLease = true
	// An unexpected supervisor exit is also fail-closed while controller lives.
	// Use the same immutable cgroup, never a recycled process identifier.
	go func() {
		_ = cmd.Wait()
		p.closeLease()
		_ = killGroup(group)
		close(p.done)
	}()
	apiSocket := filepath.Join(root, "api.sock")
	if err := retry(ctx, p.done, func() error {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", apiSocket)
		if err == nil {
			conn.Close()
		}
		return err
	}); err != nil {
		return fmt.Errorf("VM API startup: %w; initialization stderr: %s", err, diagnostic.text())
	}
	var health guestwire.Response
	initializationHash := ""
	if d.cfg.Snapshot != nil {
		if err := apiPut(ctx, apiSocket, "/snapshot/load", map[string]any{"snapshot_path": "/template.state", "mem_backend": map[string]any{"backend_path": "/template.mem", "backend_type": "File"}, "resume_vm": false}); err != nil {
			return err
		}
		if d.cfg.IO != nil {
			// Restored devices carry serialized policy. Override and verify it
			// while PAUSED, before any guest CPU or initialization is admitted.
			if err := configureSnapshotIO(ctx, apiSocket, *d.cfg.IO); err != nil {
				return err
			}
		}
		if err := apiRequest(ctx, apiSocket, "PATCH", "/vm", map[string]any{"state": "Resumed"}); err != nil {
			return err
		}
		// Restored listeners survive, but guest transport/event handling still
		// needs to resume. Retry ONLY the read-only state probe; the subsequent
		// irreversible initialize request must never receive fresh-seed retries.
		if err := waitPristine(ctx, p.done, filepath.Join(root, "v.sock")); err != nil {
			return err
		}
		if err := d.registry.markInitialization(ctx, k); err != nil {
			return err
		}
		request, err := guestinit.NewRequest(ref)
		if err != nil {
			return err
		}
		defer request.WipeEntropy()
		health, err = guestbridge.Initialize(ctx, filepath.Join(root, "v.sock"), request)
		if err != nil {
			return err
		}
		initializationHash = health.InitializationHash
	} else {
		bootArgs := "console=ttyS0 reboot=k panic=1 pci=off rdinit=/sbin/init xandbox.guest=1 xandbox.id=" + ref.ID + " xandbox.generation=" + ref.Generation
		for _, put := range []struct {
			path string
			body any
		}{
			{"/machine-config", map[string]any{"vcpu_count": 2, "mem_size_mib": 512, "smt": false}},
			{"/boot-source", map[string]any{"kernel_image_path": "/kernel", "initrd_path": "/initrd", "boot_args": bootArgs}},
			{"/drives/workspace", workspaceDrive(d.cfg.IO)},
			{"/vsock", map[string]any{"guest_cid": 3, "uds_path": "/v.sock"}},
			{"/actions", map[string]any{"action_type": "InstanceStart"}},
		} {
			if err := apiPut(ctx, apiSocket, put.path, put.body); err != nil {
				return err
			}
			if put.path == "/drives/workspace" && d.cfg.IO != nil {
				if err := verifyFrontendIO(ctx, apiSocket, *d.cfg.IO); err != nil {
					return err
				}
			}
		}
		if err := retry(ctx, p.done, func() error {
			callCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			var err error
			health, err = guestbridge.Call(callCtx, filepath.Join(root, "v.sock"), guestwire.Request{Version: guestwire.Version, Operation: "health", Ref: ref})
			return err
		}); err != nil {
			return err
		}
	}
	if d.quota != nil {
		if err := retry(ctx, p.done, func() error { return d.quota.verifyDomain(group, owner) }); err != nil {
			return err
		}
	}
	if health.ActiveGroups == nil || *health.ActiveGroups != 0 {
		return errors.New("new guest has unaccounted execution groups")
	}
	d.mu.Lock()
	p.bootID = health.BootID
	p.initializationHash = initializationHash
	d.mu.Unlock()
	return nil
}

func (d *driver) Exec(ctx context.Context, ref sandbox.Ref, req sandbox.ExecRequest, limit int) (sandbox.Output, error) {
	k, err := key(ref)
	if err != nil {
		return sandbox.Output{}, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return sandbox.Output{}, err
	}
	request := guestwire.Request{Version: guestwire.Version, Operation: "exec", Ref: ref, ExecutionID: hex.EncodeToString(id[:]), Argv: req.Argv, TimeoutMS: req.TimeoutMS, MaxOutputBytes: limit}
	if req.Generation != ref.Generation || !request.Valid() {
		return sandbox.Output{}, sandbox.ErrInvalid
	}
	d.mu.Lock()
	p := d.procs[k]
	bootID, initializationHash := "", ""
	if p != nil {
		bootID, initializationHash = p.bootID, p.initializationHash
	}
	d.mu.Unlock()
	if bootID == "" {
		return sandbox.Output{}, sandbox.ErrBackendFenced
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	case <-ctx.Done():
		return sandbox.Output{}, ctx.Err() // Never dispatched: no ambiguous guest work.
	case <-p.done:
		return sandbox.Output{}, sandbox.ErrBackendFenced
	}
	if err := ctx.Err(); err != nil {
		return sandbox.Output{}, err
	}
	_, jail := d.paths(k)
	response, callErr := guestbridge.Call(ctx, filepath.Join(jail, "root/v.sock"), request)
	if callErr == nil && response.Status == "EXITED" && response.BootID == bootID && response.InitializationHash == initializationHash && ctx.Err() == nil {
		return response.Output, nil
	}
	// The guest is not trusted to prove timeout/cancellation. Any ambiguous
	// transport, identity or execution failure destroys its host execution domain.
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stopErr := d.Stop(stopCtx, ref)
	cancel()
	if ctx.Err() != nil {
		callErr = ctx.Err()
	} else if callErr == nil {
		callErr = errors.New("guest did not return a valid completed execution")
	}
	return sandbox.Output{}, errors.Join(sandbox.ErrBackendFenced, callErr, stopErr)
}

func (d *driver) owned(ref sandbox.Ref) (string, bool, error) {
	k, err := key(ref)
	if err != nil {
		return "", false, err
	}
	exists := d.registry.owns(k)
	if !exists {
		group, jail := d.paths(k)
		for _, path := range []string{group, jail} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				return k, false, errors.New("resource exists without durable ownership")
			}
		}
	}
	return k, exists, nil
}

func (d *driver) Stop(ctx context.Context, ref sandbox.Ref) error {
	k, exists, err := d.owned(ref)
	if err != nil || !exists {
		return err
	}
	d.mu.Lock()
	p := d.procs[k]
	d.mu.Unlock()
	if p != nil {
		p.closeLease()
	}
	group, _ := d.paths(k)
	if err := killGroup(group); err != nil {
		return err
	}
	if err := retry(ctx, nil, func() error { return emptyGroup(group) }); err != nil {
		return err
	}
	if p != nil {
		select {
		case <-p.done: // Wait reaps the controller's direct child before cleanup.
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (d *driver) Cleanup(ctx context.Context, ref sandbox.Ref) error {
	k, exists, err := d.owned(ref)
	if err != nil || !exists {
		return err
	}
	if err := d.Stop(ctx, ref); err != nil {
		return err
	}
	group, jail := d.paths(k)
	if err := ctx.Err(); err != nil {
		return err
	}
	// Only the exact generation jail is recursively removed, after stop proof.
	// RemoveAll does not follow guest-controlled symlinks.
	if err := os.RemoveAll(jail); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(jail)); err != nil {
		return err
	}
	if err := os.Remove(group); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := d.registry.releaseContext(ctx, k); err != nil {
		return err
	}
	d.mu.Lock()
	delete(d.procs, k)
	d.mu.Unlock()
	return nil
}

func killGroup(group string) error {
	err := os.WriteFile(filepath.Join(group, "cgroup.kill"), []byte("1"), 0)
	if os.IsNotExist(err) {
		if _, statErr := os.Lstat(group); os.IsNotExist(statErr) {
			return nil
		}
	}
	return err
}

func emptyGroup(group string) error {
	data, err := os.ReadFile(filepath.Join(group, "cgroup.events"))
	if os.IsNotExist(err) {
		if _, statErr := os.Lstat(group); os.IsNotExist(statErr) {
			return nil
		}
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "populated 0" {
			return nil
		}
	}
	return errors.New("generation cgroup still populated")
}

func retry(ctx context.Context, done <-chan struct{}, call func() error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-done:
			return errors.New("generation supervisor exited")
		default:
		}
		if err := call(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return errors.New("generation supervisor exited")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func apiPut(ctx context.Context, socket, path string, value any) error {
	return apiRequest(ctx, socket, "PUT", path, value)
}
func apiRequest(ctx context.Context, socket, method, path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("Firecracker configuration %s rejected (%d): %s", path, response.StatusCode, body)
	}
	return nil
}

func securePath(path string) error {
	if !cleanAbsolute(path) {
		return errors.New("trusted path must be canonical and absolute")
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("trusted paths must be root-owned, non-symlink and not group/other writable")
		}
		if p == "/" {
			return nil
		}
	}
}

func privateDir(path string) error {
	if err := securePath(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if err := securePath(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private backend directory must have mode 0700")
	}
	return syncDir(filepath.Dir(path))
}

func checkAsset(asset Asset) error {
	if err := securePath(asset.Path); err != nil {
		return err
	}
	f, err := os.Open(asset.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 512<<20 {
		return errors.New("asset must be a bounded regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != asset.SHA256 {
		return errors.New("trusted asset digest mismatch")
	}
	return nil
}

func copyAsset(ctx context.Context, asset Asset, path string) error {
	if err := securePath(asset.Path); err != nil {
		return err
	}
	source, err := os.Open(asset.Path)
	if err != nil {
		return err
	}
	defer source.Close()
	dest, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer dest.Close()
	copyDest, err := assetCopySink(dest)
	if err != nil {
		return err
	}
	if err := copyAssetBytes(ctx, source, copyDest, asset.SHA256); err != nil {
		return err
	}
	// The reserved VMM UID must read cold kernel/initrd regardless of umask.
	// Workspace callers subsequently restrict and chown their private copy.
	if err := dest.Chmod(0444); err != nil {
		return err
	}
	if err := dest.Close(); err != nil {
		return err
	}
	return ctx.Err()
}

func hasWords(s string, words ...string) bool {
	set := make(map[string]bool)
	for _, word := range strings.Fields(s) {
		set[word] = true
	}
	for _, word := range words {
		if !set[word] {
			return false
		}
	}
	return true
}

func waitPristine(ctx context.Context, done <-chan struct{}, socket string) error {
	phase := ""
	if err := retry(ctx, done, func() error {
		probe, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		response, err := guestbridge.Bootstrap(probe, socket, guestinit.Request{Version: guestinit.Version, Operation: "state"})
		if response.Phase != "" {
			phase = response.Phase
			return nil
		} // FAILED is valid protocol, not usable capacity.
		return err
	}); err != nil {
		return err
	}
	if phase != guestinit.Waiting {
		return errors.New("restored template is not unassigned; initialization retry is forbidden")
	}
	return nil
}

func (d *driver) CheckAdmission(l sandbox.AdmissionLimits) error {
	if d.cfg.Node != nil {
		return d.cfg.Node.match(l, false)
	}
	return nil
}
