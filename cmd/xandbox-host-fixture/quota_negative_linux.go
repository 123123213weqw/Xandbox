//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: ordinary daemon rejection/EDQUOT checks in our private L1. Each
// fixed case has its own backend binding; never mutate a live bound policy.
import (
	"context"
	"errors"
	"fmt"
	"io"
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

var negativeQuotaCases = [...]string{"cap", "uuid", "unknown", "binding", "block", "inode"}

func validNegativeCase(name string) bool {
	for _, v := range negativeQuotaCases {
		if name == v {
			return true
		}
	}
	return false
}
func negativeBase(name string) (string, error) {
	if !validNegativeCase(name) {
		return "", errors.New("fixed negative quota case required")
	}
	return "/srv/nq/" + name, nil
}
func negativeDaemonArgs(name string) ([]string, error) {
	base, e := negativeBase(name)
	if e != nil {
		return nil, e
	}
	return []string{"sandboxd", "-backend", "firecracker", "-state-dir", base + "/s", "-auth-file", "/srv/config/auth.json", "-firecracker-config", base + "/backend.json", "-max-instances", "1"}, nil
}
func runNegativeQuotaDaemon(name string) error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	args, e := negativeDaemonArgs(name)
	if e != nil {
		return e
	}
	if name == "cap" {
		return errors.New("capability negative is launched directly by L1 PID1 only")
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	return unix.Exec("/srv/assets/sandboxd", args, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}

type negativeDaemon struct {
	cmd     *exec.Cmd
	done    chan struct{}
	waitErr error
}

func startNegativeDaemon(ctx context.Context, name, stage string) (*negativeDaemon, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	base, e := negativeBase(name)
	if e != nil {
		return nil, e
	}
	if stage != "first" && !(name == "binding" && stage == "changed") && !((name == "block" || name == "inode") && stage == "restart") {
		return nil, errors.New("fixed launch stage required")
	}
	log, e := os.OpenFile(base+"/"+stage+".log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	c := exec.CommandContext(ctx, "/usr/bin/xandbox-host-fixture", "-mode", "quota-negative-"+name)
	if name == "cap" {
		args, e := negativeDaemonArgs(name)
		if e != nil {
			return nil, e
		}
		c = exec.CommandContext(ctx, "/srv/assets/sandboxd", args[1:]...)
	}
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	c.Stdout, c.Stderr = log, log
	if e = c.Start(); e != nil {
		return nil, e
	}
	p := &negativeDaemon{cmd: c, done: make(chan struct{})}
	go func() { p.waitErr = c.Wait(); close(p.done) }()
	return p, nil
}
func (p *negativeDaemon) stop() error {
	select {
	case <-p.done:
		return p.waitErr
	default:
	}
	if e := p.cmd.Process.Signal(unix.SIGTERM); e != nil && !errors.Is(e, os.ErrProcessDone) {
		return e
	}
	select {
	case <-p.done:
		return p.waitErr
	case <-time.After(15 * time.Second):
		return errors.New("owned negative daemon not reaped; retain resources")
	}
}
func expectNegativeExit(ctx context.Context, p *negativeDaemon, base, stage, expected string) error {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("negative daemon did not reject startup")
	case <-p.done:
	}
	if p.waitErr == nil || ctx.Err() != nil {
		return errors.New("negative daemon succeeded or context expired")
	}
	b, e := os.ReadFile(base + "/" + stage + ".log")
	if e != nil {
		return e
	}
	if len(b) > 65536 || !strings.Contains(string(b), expected) {
		return errors.New("specific ordinary daemon rejection not observed")
	}
	if _, e := os.Lstat(base + "/s/api.sock"); !os.IsNotExist(e) {
		return errors.New("rejected daemon exposed API socket")
	}
	return nil
}
func negativeQuotaClear(q *quotaFS) error {
	for id := quotaFirst; id < quotaFirst+3; id++ {
		r, e := q.get(id)
		if e != nil {
			return e
		}
		if !quotaEmpty(r) {
			return errors.New("negative project not empty")
		}
	}
	return nil
}
func negativeReady(ctx context.Context, p *negativeDaemon, api *client.Client) error {
	return waitNode(ctx, func() (bool, error) {
		select {
		case <-p.done:
			return false, errors.New("negative daemon exited before readiness")
		default:
		}
		var h struct {
			Backend    string `json:"backend"`
			Isolation  bool   `json:"isolation"`
			Production bool   `json:"production_ready"`
		}
		if e := api.Do(ctx, "GET", "/healthz", nil, &h); e != nil {
			return false, nil
		}
		if h.Backend != "firecracker" || !h.Isolation || h.Production {
			return false, errors.New("wrong negative daemon health")
		}
		return true, nil
	})
}

// Read only one atomic, bounded private envelope. Do not open FileStore.Load
// while the daemon owns the store. The returned Ref is NEVER in public output.
func negativeLedgerRef(base string, omit sandbox.Ref) (sandbox.Ref, error) {
	entries, e := os.ReadDir(base + "/s/ledger")
	if e != nil {
		return sandbox.Ref{}, e
	}
	var ref sandbox.Ref
	count, total := 0, 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if !entry.Type().IsRegular() {
			return ref, errors.New("unexpected ledger entry")
		}
		b, e := privatefile.Read(base+"/s/ledger/"+entry.Name(), 64<<10)
		if e != nil {
			return ref, e
		}
		if len(b) > 64<<10 {
			return ref, errors.New("oversized private ledger")
		}
		var envelope struct {
			Version int            `json:"version"`
			Record  sandbox.Record `json:"record"`
		}
		if e = strictjson.Decode(b, &envelope); e != nil {
			return ref, e
		}
		if envelope.Version != 1 || len(envelope.Record.ID) != 32 || len(envelope.Record.Generation) != 32 || strings.Trim(envelope.Record.ID+envelope.Record.Generation, "0123456789abcdef") != "" || entry.Name() != envelope.Record.ID+".json" {
			return ref, errors.New("invalid private envelope")
		}
		total++
		if envelope.Record.Ref == omit {
			continue
		}
		ref = envelope.Record.Ref
		count++
	}
	wantTotal := 1
	if omit.ID != "" {
		wantTotal = 2
	}
	if count != 1 || total != wantTotal {
		return ref, errors.New("unexpected rejected create ledger identities")
	}
	return ref, nil
}
func negativeNoResources(cfg firecracker.Config, base string, ref sandbox.Ref) error {
	k := ref.ID + ref.Generation
	for _, path := range []string{cfg.CgroupRoot + "/" + k, cfg.RuntimeRoot + "/j/firecracker/" + k, base + "/s/firecracker/" + k + ".json"} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return errors.New("rejected prepare resources remain")
		}
	}
	return nil
}
func (n *node) quotaNegativeSetup(ctx context.Context) (out map[string]any, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaDriver || n.quotaSnapshot || n.process != nil {
		return nil, errors.New("fresh ordinary quota profile required")
	}
	for _, path := range []string{"/srv/nq", "/srv/n", "/srv/state/firecracker/config.json"} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return nil, errors.New("negative setup refuses existing test resources or positive binding")
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
		return nil, errors.New("fixed cold quota seed required")
	}
	for _, path := range []string{"/srv/nq", "/srv/n"} {
		if e = os.Mkdir(path, 0700); e != nil {
			return nil, e
		}
	}
	// Bounded PRIVATE logs for diagnostics only; no log text enters the result.
	defer func() {
		if err != nil {
			for _, name := range negativeQuotaCases {
				for _, stage := range []string{"first", "changed", "restart"} {
					f, e := os.Open("/srv/nq/" + name + "/" + stage + ".log")
					if e != nil {
						continue
					}
					s, e := f.Stat()
					if e == nil {
						offset := s.Size() - 2048
						if offset < 0 {
							offset = 0
						}
						f.Seek(offset, 0)
						io.CopyN(os.Stderr, f, 2048)
					}
					f.Close()
				}
			}
			time.Sleep(time.Second)
		}
	}()
	cases := []map[string]any{}
	for index, name := range negativeQuotaCases {
		if e = negativeQuotaClear(q); e != nil {
			return nil, e
		}
		result, e := n.quotaNegativeCase(ctx, q, seed, index, name)
		if e != nil {
			return nil, fmt.Errorf("fixed quota negative %s: %w", name, e)
		}
		cases = append(cases, result)
	}
	return map[string]any{"ordinary_daemon_negative_cases": cases, "all_fixed_negative_projects_cleared": true, "positive_backend_not_yet_bound": true}, nil
}
func (n *node) quotaNegativeCase(ctx context.Context, q *quotaFS, seed firecracker.Config, index int, name string) (map[string]any, error) {
	base, e := negativeBase(name)
	if e != nil {
		return nil, e
	}
	if e = os.Mkdir(base, 0700); e != nil {
		return nil, e
	}
	if e = os.Mkdir(base+"/s", 0700); e != nil {
		return nil, e
	}
	cfg := seed
	quota := *seed.Quota
	cfg.Quota = &quota
	cfg.RuntimeRoot = "/srv/n/" + name
	cfg.CgroupRoot = "/sys/fs/cgroup/xandbox-ng-" + name
	cfg.UIDStart = 460000 + index*4
	cfg.UIDCount = 3
	cfg.Quota.ProjectStart = quotaFirst
	if e = os.Mkdir(cfg.CgroupRoot, 0700); e != nil {
		return nil, e
	}
	if e = os.WriteFile(cfg.CgroupRoot+"/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); e != nil {
		return nil, e
	}
	switch name {
	case "uuid":
		first := "0"
		if cfg.Quota.FilesystemUUID[0] == '0' {
			first = "1"
		}
		cfg.Quota.FilesystemUUID = first + cfg.Quota.FilesystemUUID[1:]
	case "block":
		cfg.Quota.MaxBytes = 16 << 20
	case "inode":
		cfg.Quota.MaxInodes = 1
	}
	if e = privateWrite(base+"/backend.json", cfg); e != nil {
		return nil, e
	}
	var unknown quotaRecord
	if name == "unknown" {
		if e = q.reserve(quotaFirst, quotaHardKiB, 16); e != nil {
			return nil, e
		}
		if e = q.sync(); e != nil {
			return nil, e
		}
		unknown, e = q.get(quotaFirst)
		if e != nil {
			return nil, e
		}
	}
	if name == "cap" {
		status, e := os.ReadFile("/proc/self/status")
		if e != nil {
			return nil, e
		}
		for _, field := range []string{"CapEff", "CapPrm", "CapBnd"} {
			present, e := capabilityPresent(string(status), field, unix.CAP_SYS_RESOURCE)
			if e != nil || !present {
				return nil, errors.New("root capability negative prerequisite missing")
			}
		}
	}
	p, e := startNegativeDaemon(ctx, name, "first")
	if e != nil {
		return nil, e
	}
	defer func() {
		if p == nil {
			return
		}
		select {
		case <-p.done:
		default:
			_ = p.stop()
		}
	}()
	result := map[string]any{"case": name, "ordinary_daemon": true}
	expected := map[string]string{"cap": "quota requires CAP_SYS_RESOURCE absent from all capability sets", "uuid": "quota runtime filesystem UUID changed", "unknown": "unowned nonempty quota record requires operator reconciliation"}
	if message, ok := expected[name]; ok {
		if e = expectNegativeExit(ctx, p, base, "first", message); e != nil {
			return nil, e
		}
		result["specific_startup_rejection_checked"] = true
		result["no_api_socket_after_rejection"] = true
		if name == "unknown" {
			after, e := q.get(quotaFirst)
			if e != nil || after != unknown {
				return nil, errors.New("unknown quota record was adopted or modified")
			}
			if e = q.clear(quotaFirst); e != nil {
				return nil, e
			}
			result["unknown_record_unchanged_before_owned_fixture_cleanup"] = true
		}
	} else {
		api := client.NewWithToken(base+"/s/api.sock", n.token)
		defer api.Close()
		if e = negativeReady(ctx, p, api); e != nil {
			return nil, e
		}
		if name == "binding" {
			bound, e := fileHash(base + "/s/firecracker/config.json")
			if e != nil {
				return nil, e
			}
			if e = p.stop(); e != nil {
				return nil, e
			}
			cfg.Quota.MaxBytes += 4096
			if e = privateWrite(base+"/backend.json", cfg); e != nil {
				return nil, e
			}
			p, e = startNegativeDaemon(ctx, name, "changed")
			if e != nil {
				return nil, e
			}
			if e = expectNegativeExit(ctx, p, base, "changed", "backend binding changed; explicit offline migration is required"); e != nil {
				return nil, e
			}
			after, e := fileHash(base + "/s/firecracker/config.json")
			if e != nil || after != bound {
				return nil, errors.New("bound policy changed during rejection")
			}
			result["changed_policy_rejected_original_binding_unchanged"] = true
		} else {
			key, e := randomKey()
			if e != nil {
				return nil, e
			}
			var rejected sandbox.Record
			if e = api.Create(ctx, key, nodeSpec(), &rejected); e == nil || !strings.Contains(e.Error(), "HTTP 500:") {
				return nil, errors.New("quota exhausted create was not refused with500")
			}
			b, e := os.ReadFile(base + "/first.log")
			if e != nil || !strings.Contains(string(b), "Firecracker preparation failed") || !strings.Contains(string(b), "disk quota exceeded") {
				return nil, errors.New("actual ordinary Prepare EDQUOT not observed")
			}
			ref, e := negativeLedgerRef(base, sandbox.Ref{})
			if e != nil {
				return nil, e
			}
			if e = waitNode(ctx, func() (bool, error) {
				var r sandbox.Record
				e := api.Do(ctx, "GET", nodePath(ref), nil, &r)
				return e == nil && r.State == sandbox.Destroyed, e
			}); e != nil {
				return nil, e
			}
			if e = negativeNoResources(cfg, base, ref); e != nil {
				return nil, e
			}
			if e = api.Create(ctx, key, nodeSpec(), &rejected); e == nil || !strings.Contains(e.Error(), "HTTP 410:") {
				return nil, errors.New("failed quota create key reused")
			}
			if e = p.stop(); e != nil {
				return nil, e
			}
			p, e = startNegativeDaemon(ctx, name, "restart")
			if e != nil {
				return nil, e
			}
			if e = negativeReady(ctx, p, api); e != nil {
				return nil, e
			}
			var recovered sandbox.Record
			if e = api.Do(ctx, "GET", nodePath(ref), nil, &recovered); e != nil || recovered.State != sandbox.Destroyed {
				return nil, errors.New("destroyed quota failure not recovered")
			}
			if e = api.Create(ctx, key, nodeSpec(), &rejected); e == nil || !strings.Contains(e.Error(), "HTTP 410:") {
				return nil, errors.New("failed quota key reused after restart")
			}
			if e = negativeNoResources(cfg, base, ref); e != nil {
				return nil, e
			}
			nextKey, e := randomKey()
			if e != nil {
				return nil, e
			}
			if e = api.Create(ctx, nextKey, nodeSpec(), &rejected); e == nil || !strings.Contains(e.Error(), "HTTP 500:") {
				return nil, errors.New("new quota attempt did not reuse released capacity")
			}
			log, e := os.ReadFile(base + "/restart.log")
			if e != nil || !strings.Contains(string(log), "Firecracker preparation failed") || !strings.Contains(string(log), "disk quota exceeded") {
				return nil, errors.New("second prepare did not hit actual quota")
			}
			nextRef, e := negativeLedgerRef(base, ref)
			if e != nil {
				return nil, e
			}
			if e = waitNode(ctx, func() (bool, error) {
				var r sandbox.Record
				e := api.Do(ctx, "GET", nodePath(nextRef), nil, &r)
				return e == nil && r.State == sandbox.Destroyed, e
			}); e != nil {
				return nil, e
			}
			if e = negativeNoResources(cfg, base, nextRef); e != nil {
				return nil, e
			}
			if e = p.stop(); e != nil {
				return nil, e
			}
			result["released_capacity_reused_second_edquot_cleaned"] = true
			result["same_binding_restart_destroyed_key410_checked"] = true
			result["actual_prepare_edquot_private_log_checked"] = true
			result["create_refused500"] = true
			result["durable_destroyed_and_exact_resources_absent"] = true
			result["old_create_key_refused410"] = true
			result["hard_bytes"] = cfg.Quota.MaxBytes
			result["hard_inodes"] = cfg.Quota.MaxInodes
		}
	}
	if e = negativeQuotaClear(q); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(cfg.CgroupRoot)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, errors.New("negative execution group retained")
		}
	}
	if e = os.Remove(cfg.CgroupRoot); e != nil {
		return nil, e
	}
	result["all_fixed_project_records_cleared"] = true
	result["owned_cgroup_root_removed"] = true
	return result, nil
}
