//go:build linux && xandbox_host_fixture

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const fixtureMarker = "Xandbox nested host fixture v1\n"
const nodeGroup = "/sys/fs/cgroup/xandbox"

type nodeRequest struct {
	Version   int             `json:"version"`
	Operation string          `json:"operation"`
	Phase     string          `json:"phase,omitempty"`
	Receipt   json.RawMessage `json:"receipt,omitempty"`
}
type nodeReceipt struct {
	Phase               string
	Ref                 sandbox.Ref
	Key, L1Boot, L2Boot string
}
type node struct {
	quotaDriver     bool
	nodeBudget      bool
	nodeLoad        bool
	loadTokenB      string
	nodeSnapshot    bool
	quotaSnapshot   bool
	quotaSwitch     bool
	switchTokenB    string
	switchTemplate  string
	quotaStateIO    bool
	quotaWindowLock *os.File
	quotaHeld       *quotaBarrierLive
	quotaLost       *quotaLossLive
	copyCut         *copyCutLive
	ownerCut        *ownerCutLive
	mapper          *stateMapper
	api             *client.Client
	process         *exec.Cmd
	exited          chan error
	token, boot     string
}

func (q nodeRequest) validate() error {
	if q.Version != 1 {
		return errors.New("bad fixture protocol")
	}
	if q.Operation == "quota-copy-cut-recover" || q.Operation == "quota-owner-cut-recover" {
		if q.Phase != "" || len(q.Receipt) == 0 || len(q.Receipt) > copyCutReceiptMax {
			return errors.New("bounded fixed private cut receipt required")
		}
		return nil
	}
	if len(q.Receipt) > 0 {
		return errors.New("receipt only allowed on fixed private cold recovery")
	}

	switch q.Operation {
	case "node-diagnostics-checkpoint", "node-diagnostics-recover":
		if !diagnosticHoldMode(q.Phase).valid() {
			return errors.New("fixed diagnostic hold phase required")
		}
	case "node-tls-policy-checkpoint", "node-tls-policy-recover":
		if !tlsPolicyMode(q.Phase).valid() {
			return errors.New("fixed TLS policy phase required")
		}
	case "node-operator-store-checkpoint", "node-operator-store-recover":
		if !operatorStoreMode(q.Phase).valid() {
			return errors.New("fixed operator store phase required")
		}
	case "node-tls-gateway-checkpoint", "node-tls-gateway-recover", "node-operator-shutdown-checkpoint", "node-operator-shutdown-recover", "node-session-ticket-checkpoint", "node-session-ticket-recover", "probe", "recover", "quota-probe", "quota-snapshot-setup", "quota-copy-setup", "quota-copy-cut-checkpoint", "quota-owner-cut-checkpoint", "node-load-run", "node-load-recover", "node-oom-checkpoint", "node-oom-recover", "node-budget-checkpoint", "node-budget-recover", "node-operator-checkpoint", "node-operator-recover", "node-snapshot-checkpoint", "node-snapshot-recover", "node-prepare-cancel", "quota-switch-setup", "quota-switch-run", "quota-switch-checkpoint", "quota-switch-recover", "quota-negative-setup", "quota-syscall-setup", "quota-listener-reserve-checkpoint", "quota-listener-reserve-recover", "quota-listener-release-checkpoint", "quota-listener-release-recover", "quota-barrier-checkpoint", "quota-barrier-recover", "quota-commit-eio-checkpoint", "quota-commit-eio-recover", "quota-preclear-hold-checkpoint", "quota-preclear-hold-recover", "quota-postclear-hold-checkpoint", "quota-postclear-hold-recover", "quota-unenforced", "quota-clear-checkpoint", "quota-clear-recover":
		if q.Phase != "" {
			return errors.New("unexpected phase")
		}
	case "checkpoint", "quota-checkpoint":
		if q.Phase != "running" && q.Phase != "stopped" && q.Phase != "destroyed" {
			return errors.New("invalid checkpoint phase")
		}
	case "io-fault":
		if q.Phase != "eio-busy" && q.Phase != "eio-idle" && q.Phase != "hang-busy" && q.Phase != "hang-idle" {
			return errors.New("invalid fixed I/O fault case")
		}
	default:
		return errors.New("unknown fixed fixture operation")
	}
	return nil
}

func privateWrite(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	b = append(b, '\n')
	f, e := os.CreateTemp(filepath.Dir(path), ".fixture-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

func randomKey() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func nodeSpec() sandbox.CreateRequest {
	return sandbox.CreateRequest{TTLMS: 300000, Limits: sandbox.Limits{MaxExecMS: 60000, MaxOutputBytes: 8192}}
}
func nodePath(r sandbox.Ref) string { return "/v1/sandboxes/" + r.ID }
func generationBody(r sandbox.Ref) map[string]string {
	return map[string]string{"generation": r.Generation}
}

func waitNode(ctx context.Context, f func() (bool, error)) error {
	for {
		ok, e := f()
		if e != nil {
			return e
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (n *node) initialize() error {
	for _, p := range []string{"/srv/config", "/srv/fixture", "/srv/state"} {
		if e := os.MkdirAll(p, 0700); e != nil {
			return e
		}
	}
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return e
	}
	n.boot = strings.TrimSpace(string(b))
	b, e = os.ReadFile("/srv/fixture/token")
	if os.IsNotExist(e) {
		n.token, e = randomKey()
		if e != nil {
			return e
		}
		if e = privateWrite("/srv/fixture/token", n.token); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else if e = json.Unmarshal(b, &n.token); e != nil {
		return e
	}
	if n.quotaSwitch {
		if e = n.initializeQuotaSwitch(); e != nil {
			return e
		}
	}
	if n.nodeLoad {
		if e = n.initializeNodeLoadAuth(); e != nil {
			return e
		}
	}
	capacity := 1
	if n.quotaSnapshot {
		capacity = 2
	}
	if n.nodeBudget {
		capacity = 4
	}
	h := sha256.Sum256([]byte(n.token))
	if _, e = os.Stat("/srv/config/auth.json"); os.IsNotExist(e) {
		if e = privateWrite("/srv/config/auth.json", map[string]any{"version": 1, "keys": []any{map[string]any{"tenant_id": "nested-fixture", "max_instances": capacity, "token_sha256": hex.EncodeToString(h[:])}}}); e != nil {
			return e
		}
	}
	if e = os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); e != nil {
		return e
	}
	if e = os.Mkdir(nodeGroup, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	if e = os.WriteFile(nodeGroup+"/cgroup.subtree_control", []byte("+memory +pids +cpu"), 0); e != nil {
		return e
	}
	if n.nodeBudget {
		if n.nodeLoad {
			e = n.initializeNodeLoad()
		} else if n.nodeSnapshot {
			e = n.initializeNodeSnapshotBudget()
		} else {
			e = n.initializeNodeBudget()
		}
		if e != nil {
			return e
		}
	}
	n.api = client.NewWithToken("/srv/state/api.sock", n.token)
	return nil
}

func kvmAvailable() error {
	f, e := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	v, e := unix.IoctlRetInt(int(f.Fd()), 0xae00)
	if e != nil || v != 12 {
		return errors.New("real nested KVM API12 required")
	}
	return nil
}

func (n *node) start(ctx context.Context) error {
	if n.process != nil {
		select {
		case <-n.exited:
			return errors.New("controller already exited; fresh boot required")
		default:
			return nil
		}
	}
	log, e := os.OpenFile("/srv/fixture/controller.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer log.Close()
	n.process = exec.Command("/srv/assets/sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "1", "-metrics")
	if n.quotaDriver {
		mode := "quota-daemon-drop"
		if n.quotaSnapshot {
			mode = "quota-snapshot-daemon-drop"
		}
		if n.quotaSwitch {
			mode = "quota-switch-daemon-drop"
		}
		if n.nodeBudget {
			mode = "node-budget-daemon"
			if n.nodeLoad {
				mode = "node-load-daemon"
			}
			if n.nodeSnapshot {
				mode = "node-snapshot-daemon"
			}
		}
		n.process = exec.Command("/usr/bin/xandbox-host-fixture", "-mode", mode)
	}
	if n.nodeBudget {
		cg, err := os.Open(nodeGroup + "/control")
		if err != nil {
			return err
		}
		defer cg.Close()
		n.process.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	}
	n.process.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	n.process.Stdout, n.process.Stderr = log, log
	if e = n.process.Start(); e != nil {
		return e
	}
	n.exited = make(chan error, 1)
	go func() { n.exited <- n.process.Wait() }()
	return waitNode(ctx, func() (bool, error) {
		var h struct {
			Backend         string `json:"backend"`
			Isolation       bool   `json:"isolation"`
			ProductionReady bool   `json:"production_ready"`
		}
		select {
		case <-n.exited:
			return false, errors.New("controller exited before readiness")
		default:
		}
		e := n.api.Do(ctx, "GET", "/healthz", nil, &h)
		if e != nil {
			return false, nil
		}
		if h.Backend != "firecracker" || !h.Isolation || h.ProductionReady {
			return false, errors.New("wrong backend or readiness claim")
		}
		return true, nil
	})
}

func (n *node) create(ctx context.Context, key string) (sandbox.Record, error) {
	var r sandbox.Record
	e := n.api.Create(ctx, key, nodeSpec(), &r)
	if e == nil && (r.State != sandbox.Ready || r.Backend != "firecracker") {
		e = errors.New("real READY required")
	}
	return r, e
}
func (n *node) submit(ctx context.Context, r sandbox.Ref, argv []string) (sandbox.Job, error) {
	var j sandbox.Job
	e := n.api.Do(ctx, "POST", nodePath(r)+"/exec", sandbox.ExecRequest{Generation: r.Generation, Argv: argv, TimeoutMS: 60000}, &j)
	return j, e
}
func (n *node) job(ctx context.Context, r sandbox.Ref, j sandbox.Job) (sandbox.Job, error) {
	var out sandbox.Job
	e := n.api.Do(ctx, "GET", nodePath(r)+"/executions/"+j.ID, nil, &out)
	return out, e
}
func (n *node) execute(ctx context.Context, r sandbox.Ref, argv []string) (sandbox.Output, error) {
	j, e := n.submit(ctx, r, argv)
	if e != nil {
		return sandbox.Output{}, e
	}
	var out sandbox.Job
	e = waitNode(ctx, func() (bool, error) {
		var e error
		out, e = n.job(ctx, r, j)
		return e == nil && out.Status != "RUNNING", e
	})
	if e != nil {
		return sandbox.Output{}, e
	}
	if out.Status != "EXITED" || out.Output.ExitCode != 0 {
		return out.Output, errors.New("fixed guest command failed")
	}
	return out.Output, nil
}

func actualNestedVM(r sandbox.Ref) error {
	group := nodeGroup + "/" + r.ID + r.Generation
	procs, e := os.ReadFile(group + "/cgroup.procs")
	if e != nil {
		return e
	}
	for _, pid := range strings.Fields(string(procs)) {
		fds, e := os.ReadDir("/proc/" + pid + "/fd")
		if e != nil {
			return e
		}
		for _, fd := range fds {
			target, _ := os.Readlink("/proc/" + pid + "/fd/" + fd.Name())
			if strings.Contains(target, "kvm-vm") {
				return nil
			}
		}
	}
	return errors.New("nested guest lacks real VM FD in owned group")
}

func (n *node) destroy(ctx context.Context, r sandbox.Ref) error {
	var v sandbox.Record
	if e := n.api.Do(ctx, "DELETE", nodePath(r), generationBody(r), &v); e != nil {
		return e
	}
	return waitNode(ctx, func() (bool, error) {
		e := n.api.Do(ctx, "GET", nodePath(r), nil, &v)
		return e == nil && v.State == sandbox.Destroyed, e
	})
}

func (n *node) clean(r sandbox.Ref) error {
	key := r.ID + r.Generation
	for _, p := range []string{nodeGroup + "/" + key, "/srv/r/j/firecracker/" + key, "/srv/state/firecracker/" + key + ".json"} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return errors.New("old owned resource retained")
		}
	}
	return nil
}

func (n *node) checkpoint(ctx context.Context, phase string) (map[string]any, error) {
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
	b, e := n.execute(ctx, r.Ref, []string{"cat", "/proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, e
	}
	j, e := n.submit(ctx, r.Ref, []string{"sh", "-c", "echo ready > power-ready; sleep 120 & sleep 120 & wait"})
	if e != nil {
		return nil, e
	}
	if _, e = n.execute(ctx, r.Ref, []string{"sh", "-c", "while [ ! -f power-ready ]; do sleep 0.01; done"}); e != nil {
		return nil, e
	}
	job, e := n.job(ctx, r.Ref, j)
	if e != nil || job.Status != "RUNNING" {
		return nil, errors.New("busy guest not running at checkpoint")
	}
	if phase == "stopped" {
		var stopped sandbox.Record
		if e = n.api.Do(ctx, "POST", nodePath(r.Ref)+"/stop", generationBody(r.Ref), &stopped); e != nil {
			return nil, e
		}
		if stopped.State != sandbox.Stopped || stopped.StoppedAt.IsZero() {
			return nil, errors.New("durable STOPPED not confirmed")
		}
	}
	if phase == "destroyed" {
		if e = n.destroy(ctx, r.Ref); e != nil {
			return nil, e
		}
		if e = n.clean(r.Ref); e != nil {
			return nil, e
		}
	}
	receipt := nodeReceipt{Phase: phase, Ref: r.Ref, Key: key, L1Boot: n.boot, L2Boot: strings.TrimSpace(b.Stdout)}
	if e = privateWrite("/srv/fixture/receipt.json", receipt); e != nil {
		return nil, e
	}
	return map[string]any{"phase": phase, "real_nested_kvm": true, "guest_uid_checked": true, "checkpoint_receipt_fsynced": true}, nil
}

func (n *node) recover(ctx context.Context) (map[string]any, error) {
	b, e := os.ReadFile("/srv/fixture/receipt.json")
	if e != nil {
		return nil, e
	}
	var old nodeReceipt
	if e = strictjson.Decode(b, &old); e != nil {
		return nil, e
	}
	if old.L1Boot == n.boot || old.L1Boot == "" {
		return nil, errors.New("L1 boot identity did not change")
	}
	began := time.Now()
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	var r sandbox.Record
	if e = waitNode(ctx, func() (bool, error) {
		e := n.api.Do(ctx, "GET", nodePath(old.Ref), nil, &r)
		return e == nil && r.State == sandbox.Destroyed, e
	}); e != nil {
		return nil, e
	}
	if e = n.clean(old.Ref); e != nil {
		return nil, e
	}
	var replay sandbox.Record
	e = n.api.Create(ctx, old.Key, nodeSpec(), &replay)
	if e == nil || !strings.HasPrefix(e.Error(), "HTTP 410:") {
		return nil, errors.New("old key resurrected after host restart")
	}
	recoveryMS := float64(time.Since(began).Microseconds()) / 1000
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	fresh, e := n.create(ctx, key)
	if e != nil {
		return nil, e
	}
	if fresh.Ref == old.Ref {
		return nil, errors.New("old generation reused")
	}
	if e = actualNestedVM(fresh.Ref); e != nil {
		return nil, e
	}
	u, e := n.execute(ctx, fresh.Ref, []string{"id", "-u"})
	if e != nil || strings.TrimSpace(u.Stdout) != "65534" {
		return nil, errors.New("wrong fresh guest UID")
	}
	boot, e := n.execute(ctx, fresh.Ref, []string{"cat", "/proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, e
	}
	if strings.TrimSpace(boot.Stdout) == old.L2Boot {
		return nil, errors.New("old guest resurrected")
	}
	if _, e = n.execute(ctx, fresh.Ref, []string{"true"}); e != nil {
		return nil, e
	}
	if e = n.destroy(ctx, fresh.Ref); e != nil {
		return nil, e
	}
	if e = n.clean(fresh.Ref); e != nil {
		return nil, e
	}
	return map[string]any{"phase": old.Phase, "l1_boot_changed": true, "old_durable_destroyed": true, "old_resources_absent": true, "old_key_refused_410": true, "fresh_real_kvm_exec_destroy": true, "fresh_guest_boot_changed": true, "daemon_start_to_old_reclaimed_ms": recoveryMS}, nil
}

func requireNode() error {
	marker, e := os.ReadFile("/etc/xandbox-host-fixture")
	if e != nil || string(marker) != fixtureMarker || os.Geteuid() != 0 || os.Getpid() != 1 {
		return errors.New("isolated L1 PID1 fixture marker required")
	}
	return nil
}

func runNode() error { return runNodeProfile(false) }

func runNodeProfile(stateIO bool) error { return runNodeOptions(stateIO, false) }

func runNodeOptions(stateIO, quotaProbe bool) error {
	return runNodeProfiles(stateIO, quotaProbe, false)
}
func runNodeProfiles(stateIO, quotaProbe, quotaDriver bool) error {
	return runNodeAllProfiles(stateIO, quotaProbe, quotaDriver, false)
}
func runNodeAllProfiles(stateIO, quotaProbe, quotaDriver, quotaSnapshot bool) error {
	return runNodeQuotaIOProfiles(stateIO, quotaProbe, quotaDriver, quotaSnapshot, false)
}
func runNodeQuotaIOProfiles(stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO bool) error {
	return runNodeQuotaSwitchProfiles(stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO, false)
}
func runNodeQuotaSwitchProfiles(stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO, quotaSwitch bool) error {
	return runNodeBudgetProfiles(stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO, quotaSwitch, false)
}
func runNodeBudgetProfiles(stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO, quotaSwitch, nodeBudget bool) error {
	return runNodeEnvelopeProfiles(stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO, quotaSwitch, nodeBudget, false)
}
func runNodeEnvelopeProfiles(stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO, quotaSwitch, nodeBudget, nodeSnapshot bool) error {
	return runNodeProfileSet(stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO, quotaSwitch, nodeBudget, nodeSnapshot, false)
}
func runNodeLoadProfile() error {
	return runNodeProfileSet(false, false, true, false, false, false, true, false, true)
}
func runNodeProfileSet(stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO, quotaSwitch, nodeBudget, nodeSnapshot, nodeLoad bool) error {
	if nodeLoad && (!nodeBudget || !quotaDriver || stateIO || quotaProbe || quotaSnapshot || quotaStateIO || quotaSwitch || nodeSnapshot) {
		return errors.New("exclusive fixed node-load image required")
	}
	if nodeSnapshot && (stateIO || quotaProbe || quotaDriver || quotaSnapshot || quotaStateIO || quotaSwitch || nodeBudget) {
		return errors.New("exclusive node snapshot profile required")
	}
	if nodeBudget && (stateIO || quotaProbe || quotaSnapshot || quotaStateIO || quotaSwitch || !quotaDriver) {
		return errors.New("exclusive node-budget driver profile required")
	}
	count := 0
	for _, enabled := range []bool{stateIO, quotaProbe, quotaDriver, quotaSnapshot, quotaStateIO, quotaSwitch} {
		if enabled {
			count++
		}
	}
	if count > 1 {
		return errors.New("exclusive L1 image profile required")
	}
	quotaDriver = quotaDriver || quotaSnapshot || quotaStateIO || quotaSwitch || nodeSnapshot
	quotaSnapshot = quotaSnapshot || quotaSwitch || nodeSnapshot
	nodeBudget = nodeBudget || nodeSnapshot
	stateIO = stateIO || quotaStateIO
	if e := requireNode(); e != nil {
		return e
	}
	var mapper *stateMapper
	if stateIO {
		var e error
		mapper, e = setupStateMapper()
		if e != nil {
			return e
		}
		defer mapper.close()
		mountOptions := "errors=remount-ro"
		if quotaStateIO {
			mountOptions += ",prjquota"
		}
		if e = unix.Mount(stateDevice, "/srv", "ext4", unix.MS_NOSUID, mountOptions); e != nil {
			return e
		}
	}
	serial, e := os.OpenFile("/dev/ttyS1", os.O_RDWR|unix.O_NOCTTY, 0)
	if e != nil {
		return e
	}
	defer serial.Close()
	t, e := unix.IoctlGetTermios(int(serial.Fd()), unix.TCGETS)
	if e != nil {
		return e
	}
	t.Iflag = 0
	t.Oflag = 0
	t.Lflag = 0
	t.Cflag = unix.B115200 | unix.CS8 | unix.CREAD | unix.CLOCAL
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
	if e = unix.IoctlSetTermios(int(serial.Fd()), unix.TCSETS, t); e != nil {
		return e
	}
	n := &node{quotaDriver: quotaDriver, quotaSnapshot: quotaSnapshot, quotaStateIO: quotaStateIO, quotaSwitch: quotaSwitch, mapper: mapper, nodeBudget: nodeBudget, nodeSnapshot: nodeSnapshot, nodeLoad: nodeLoad}
	if e = n.initialize(); e != nil {
		return e
	}
	fmt.Fprintln(os.Stderr, "XANDBOX_NESTED_HOST_READY")
	scan := bufio.NewScanner(serial)
	scan.Buffer(make([]byte, 1024), 8192)
	for scan.Scan() {
		q := nodeRequest{}
		out := map[string]any{"version": 1, "ok": false}
		e := strictjson.Decode(scan.Bytes(), &q)
		if e == nil {
			e = q.validate()
		}
		if e == nil {
			timeout := 70 * time.Second
			if q.Operation == "node-diagnostics-checkpoint" || q.Operation == "node-diagnostics-recover" || q.Operation == "node-tls-policy-checkpoint" || q.Operation == "node-tls-policy-recover" || q.Operation == "node-tls-gateway-checkpoint" || q.Operation == "node-tls-gateway-recover" || q.Operation == "node-operator-shutdown-checkpoint" || q.Operation == "node-operator-shutdown-recover" || q.Operation == "node-session-ticket-checkpoint" || q.Operation == "node-session-ticket-recover" || q.Operation == "node-operator-store-checkpoint" || q.Operation == "node-operator-store-recover" || q.Operation == "node-operator-checkpoint" || q.Operation == "node-operator-recover" || q.Operation == "node-snapshot-checkpoint" || q.Operation == "node-snapshot-recover" || q.Operation == "node-oom-checkpoint" || q.Operation == "node-oom-recover" || q.Operation == "node-budget-checkpoint" || q.Operation == "node-budget-recover" || q.Operation == "quota-owner-cut-checkpoint" || q.Operation == "quota-owner-cut-recover" || q.Operation == "quota-copy-cut-checkpoint" || q.Operation == "quota-copy-cut-recover" || q.Operation == "quota-copy-setup" || q.Operation == "quota-snapshot-setup" || q.Operation == "quota-negative-setup" || q.Operation == "quota-syscall-setup" {
				timeout = 200 * time.Second
			}
			if q.Operation == "quota-switch-setup" || q.Operation == "quota-switch-recover" {
				timeout = 200 * time.Second
			}
			if q.Operation == "quota-switch-run" {
				timeout = switchRunBudget
			}
			if q.Operation == "node-load-run" {
				timeout = nodeLoadRunBudget
			}
			if q.Operation == "node-load-recover" {
				timeout = 200 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			var result map[string]any
			switch q.Operation {
			case "node-tls-policy-checkpoint":
				result, e = n.nodeTLSPolicyCheckpoint(ctx, tlsPolicyMode(q.Phase))
			case "node-tls-policy-recover":
				result, e = n.nodeTLSPolicyRecover(ctx, tlsPolicyMode(q.Phase))
			case "probe":
				e = kvmAvailable()
				if e == nil {
					result = map[string]any{"nested_kvm_api": 12, "l1_pid1_fixture": true}
				}
			case "checkpoint":
				result, e = n.checkpoint(ctx, q.Phase)
			case "quota-snapshot-setup":
				if !quotaSnapshot {
					e = errors.New("fixed quota snapshot profile required")
				} else {
					result, e = n.quotaSnapshotSetup(ctx)
				}
			case "quota-copy-setup":
				result, e = n.quotaCopySetup(ctx)
			case "node-prepare-cancel":
				result, e = n.nodePrepareCancel(ctx)
			case "node-snapshot-checkpoint":
				result, e = n.nodeSnapshotCheckpoint(ctx)
			case "node-snapshot-recover":
				result, e = n.nodeSnapshotRecover(ctx)
			case "node-tls-gateway-checkpoint":
				result, e = n.nodeTLSGatewayCheckpoint(ctx)
			case "node-tls-gateway-recover":
				result, e = n.nodeTLSGatewayRecover(ctx)
			case "node-diagnostics-checkpoint":
				result, e = n.diagnosticCheckpoint(ctx, diagnosticHoldMode(q.Phase))
			case "node-diagnostics-recover":
				result, e = n.diagnosticRecover(ctx, diagnosticHoldMode(q.Phase))
			case "node-operator-shutdown-checkpoint":
				result, e = n.nodeOperatorShutdownCheckpoint(ctx)
			case "node-operator-shutdown-recover":
				result, e = n.nodeOperatorShutdownRecover(ctx)
			case "node-session-ticket-checkpoint":
				result, e = n.nodeSessionTicketCheckpoint(ctx)
			case "node-session-ticket-recover":
				result, e = n.nodeSessionTicketRecover(ctx)
			case "node-operator-store-checkpoint":
				result, e = n.nodeOperatorStoreCheckpoint(ctx, operatorStoreMode(q.Phase))
			case "node-operator-store-recover":
				result, e = n.nodeOperatorStoreRecover(ctx, operatorStoreMode(q.Phase))
			case "node-operator-checkpoint":
				result, e = n.nodeOperatorCheckpoint(ctx)
			case "node-operator-recover":
				result, e = n.nodeOperatorRecover(ctx)
			case "node-load-run":
				result, e = n.nodeLoadRun(ctx)
			case "node-load-recover":
				result, e = n.nodeLoadRecover(ctx)
			case "node-oom-checkpoint":
				result, e = n.nodeOOMCheckpoint(ctx)
			case "node-oom-recover":
				result, e = n.nodeOOMRecover(ctx)
			case "node-budget-checkpoint":
				result, e = n.nodeBudgetCheckpoint(ctx)
			case "node-budget-recover":
				result, e = n.nodeBudgetRecover(ctx)
			case "quota-owner-cut-checkpoint":
				var private []byte
				result, private, e = n.quotaOwnerCutCheckpoint(ctx)
				if e == nil {
					out["private_receipt"] = json.RawMessage(private)
				}
			case "quota-owner-cut-recover":
				result, e = n.quotaOwnerCutRecover(ctx, q.Receipt)
			case "quota-copy-cut-checkpoint":
				var private []byte
				result, private, e = n.quotaCopyCutCheckpoint(ctx)
				if e == nil {
					out["private_receipt"] = json.RawMessage(private)
				}
			case "quota-copy-cut-recover":
				result, e = n.quotaCopyCutRecover(ctx, q.Receipt)
			case "quota-switch-setup":
				result, e = n.quotaSwitchSetup(ctx)
			case "quota-switch-run":
				result, e = n.quotaSwitchRun(ctx)
				if result != nil {
					out["result"] = result
				} // Retain bounded sanitized incomplete rows, too.
			case "quota-switch-checkpoint":
				result, e = n.quotaSwitchCheckpoint(ctx)
			case "quota-switch-recover":
				result, e = n.quotaSwitchRecover(ctx)
			case "quota-clear-checkpoint":
				result, e = n.quotaClearCheckpoint(ctx)
			case "quota-clear-recover":
				result, e = n.recoverQuotaClear(ctx)
			case "quota-unenforced":
				result, e = n.quotaUnenforced(ctx)
			case "quota-negative-setup":
				result, e = n.quotaNegativeSetup(ctx)
			case "quota-syscall-setup":
				result, e = n.quotaSyscallSetup(ctx)
			case "quota-listener-reserve-checkpoint":
				result, e = n.quotaListenerCheckpoint(ctx, quotaLossReserve)
			case "quota-listener-reserve-recover":
				result, e = n.quotaListenerRecover(ctx, quotaLossReserve)
			case "quota-listener-release-checkpoint":
				result, e = n.quotaListenerCheckpoint(ctx, quotaLossRelease)
			case "quota-listener-release-recover":
				result, e = n.quotaListenerRecover(ctx, quotaLossRelease)
			case "quota-barrier-checkpoint":
				result, e = n.quotaBarrierCheckpoint(ctx)
			case "quota-barrier-recover":
				result, e = n.recoverQuotaBarrier(ctx)
			case "quota-commit-eio-checkpoint":
				result, e = n.quotaBarrierCheckpointOn(ctx, quotaReserveEIO)
			case "quota-commit-eio-recover":
				result, e = n.recoverQuotaBarrierOn(ctx, quotaReserveEIO)
			case "quota-preclear-hold-checkpoint":
				result, e = n.quotaBarrierCheckpointOn(ctx, quotaReleasePreHold)
			case "quota-preclear-hold-recover":
				result, e = n.recoverQuotaBarrierOn(ctx, quotaReleasePreHold)
			case "quota-postclear-hold-checkpoint":
				result, e = n.quotaBarrierCheckpointOn(ctx, quotaReleasePostHold)
			case "quota-postclear-hold-recover":
				result, e = n.recoverQuotaBarrierOn(ctx, quotaReleasePostHold)
			case "quota-checkpoint":
				if !quotaDriver {
					e = errors.New("ordinary driver quota image profile required")
				} else {
					result, e = n.quotaDriverCheckpoint(ctx, q.Phase)
				}
			case "io-fault":
				if mapper == nil {
					e = errors.New("isolated state-I/O image profile required")
				} else {
					result, e = n.ioFault(ctx, mapper, q.Phase)
				}
			case "quota-probe":
				if !quotaProbe {
					e = errors.New("isolated quota-prerequisite profile required")
				} else {
					result, e = n.quotaProbe(ctx)
				}
			case "recover":
				var quotaResult map[string]any
				if quotaProbe {
					quotaResult, e = recoverQuotaProbe()
				}
				if e == nil && quotaDriver {
					quotaResult, e = verifyDriverQuotaColdBootOn(mapper)
				}
				if e == nil {
					e = kvmAvailable()
				}
				if e == nil {
					result, e = n.recover(ctx)
					if e == nil && quotaDriver {
						e = driverQuotaAllClearOn(mapper)
						if e == nil {
							quotaResult["all_private_project_ids_cleared"] = true
						}
					}
					if e == nil {
						for k, v := range quotaResult {
							result[k] = v
						}
					}
				}
			}
			cancel()
			if q.Operation == "node-load-run" && result != nil {
				out["result"] = result
			}
			if e == nil {
				out["ok"] = true
				out["result"] = result
			}
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, "private node step failure:", e)
			// Root fixture diagnostics ONLY on the private L1 console. Never
			// add these fields to a tenant API or sanitized acceptance report.
			if log, openErr := os.Open("/srv/fixture/controller.log"); openErr == nil {
				if info, statErr := log.Stat(); statErr == nil {
					offset := info.Size() - 16384
					if offset < 0 {
						offset = 0
					}
					_, _ = log.Seek(offset, 0)
					_, _ = io.CopyN(os.Stderr, log, 16384)
				}
				_ = log.Close()
			}
			if quotaDriver && q.Operation == "recover" {
				if diag, diagErr := driverQuotaDiagnosticOn(mapper); diagErr == nil {
					out["quota_diagnostic"] = diag
				}
			}
			out["error"] = "FIXTURE_STEP_FAILED"
		}
		if e = json.NewEncoder(serial).Encode(out); e != nil {
			return e
		}
	}
	return scan.Err()
}
