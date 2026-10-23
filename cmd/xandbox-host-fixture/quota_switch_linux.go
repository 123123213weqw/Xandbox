//go:build linux && xandbox_host_fixture

package main

// TEST ONLY fixed two-tenant, quota-enabled service profile. All workload argv
// below goes through the ordinary guest API; never execute it on L1/L0.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

const switchCycles = 120
const switchMinimumSeconds = 180
const switchSlots = 8
const switchCapacity = 4
const switchReceiptPath = "/srv/fixture/quota-switch-receipt.json"

var switchTenants = [2]string{"switch-alpha", "switch-beta"}

type switchAPI struct {
	http  *http.Client
	token string
}

func newSwitchAPI(socket, token string) *switchAPI {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &switchAPI{http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, token: token}
}
func (c *switchAPI) close() { c.http.CloseIdleConnections() }
func (c *switchAPI) call(ctx context.Context, method, path, key string, body, out any, want int) error {
	var b []byte
	var e error
	if body != nil {
		b, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://fixture.local"+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	r, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	b, e = io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return errors.New("bounded fixed API reply exceeded")
	}
	if r.StatusCode != want {
		return fmt.Errorf("fixed switch API status %d expected %d", r.StatusCode, want)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
func switchRefValid(ref sandbox.Ref) bool {
	return len(ref.ID) == 32 && len(ref.Generation) == 32 && strings.Trim(ref.ID+ref.Generation, "0123456789abcdef") == ""
}
func switchPath(ref sandbox.Ref) string      { return "/v1/sandboxes/" + ref.ID }
func switchGuestSpec() sandbox.CreateRequest { return nodeSpec() }
func switchKnown(r quotaRecord) bool {
	return quotaEmpty(r) || (r.BHard == 192<<10 && r.IHard == 128 && r.BSoft|r.ISoft|r.BTime|r.ITime == 0 && r.Space <= 192<<20 && r.Inodes <= 128)
}
func switchQuotaRead(q *quotaFS, id uint32) (quotaRecord, error) {
	var r quotaRecord
	if e := requireNode(); e != nil {
		return r, e
	}
	if id < driverProjectFirst || id >= driverProjectFirst+switchSlots {
		return r, errors.New("outside eight fixed switch projects")
	}
	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL_FD, q.file.Fd(), 0x80000702, uintptr(id), uintptr(unsafe.Pointer(&r)), 0, 0)
	runtime.KeepAlive(q)
	runtime.KeepAlive(&r)
	if errno != 0 {
		return r, errno
	}
	return r, nil
}
func switchAllClear() error {
	q, e := openQuotaFS(false)
	if e != nil {
		return e
	}
	defer q.file.Close()
	for id := driverProjectFirst; id < driverProjectFirst+switchSlots; id++ {
		r, e := switchQuotaRead(q, id)
		if e != nil {
			return e
		}
		if !quotaEmpty(r) {
			return errors.New("switch project not entirely clear")
		}
	}
	return nil
}
func fixedSwitchConfig() (firecracker.Config, error) {
	var cfg firecracker.Config
	b, e := privatefile.Read("/srv/config/backend.json", 8192)
	if e != nil {
		return cfg, e
	}
	if e = strictjson.Decode(b, &cfg); e != nil {
		return cfg, e
	}
	if cfg.Version != 2 || cfg.RuntimeRoot != "/srv/r" || cfg.CgroupRoot != nodeGroup || cfg.UIDStart != 400000 || cfg.UIDCount != switchSlots || !cfg.ReservedUIDRange || cfg.Quota == nil || cfg.Quota.ProjectStart != driverProjectFirst || cfg.Quota.MaxBytes != 192<<20 || cfg.Quota.MaxInodes != 128 || cfg.Snapshot == nil || cfg.Snapshot.MemoryMiB != 512 || cfg.Snapshot.VCPUs != 2 {
		return cfg, errors.New("fixed quota switch policy mismatch")
	}
	return cfg, nil
}
func (n *node) initializeQuotaSwitch() error {
	if e := requireNode(); e != nil {
		return e
	}
	if !n.quotaSwitch || !n.quotaSnapshot || n.mapper != nil {
		return errors.New("fixed unmapped switch node required")
	}
	if _, e := fixedSwitchConfig(); e != nil {
		return e
	}
	b, e := os.ReadFile("/sys/class/block/vda/size")
	if e != nil || strings.TrimSpace(string(b)) != "8388608" {
		return errors.New("explicit 4GiB switch disk required")
	}
	b, e = privatefile.Read("/srv/fixture/token-beta", 256)
	if os.IsNotExist(e) {
		n.switchTokenB, e = randomKey()
		if e != nil {
			return e
		}
		if e = privateWrite("/srv/fixture/token-beta", n.switchTokenB); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else if e = json.Unmarshal(b, &n.switchTokenB); e != nil {
		return e
	}
	if len(n.token) != 64 || len(n.switchTokenB) != 64 || n.token == n.switchTokenB || strings.Trim(n.token+n.switchTokenB, "0123456789abcdef") != "" {
		return errors.New("invalid fixed switch tokens")
	}
	tokens := [2]string{n.token, n.switchTokenB}
	cfg := access.Config{Version: 1}
	for i, token := range tokens {
		h := sha256.Sum256([]byte(token))
		cfg.Keys = append(cfg.Keys, access.Key{TenantID: switchTenants[i], MaxInstances: 3, TokenSHA256: hex.EncodeToString(h[:])})
	}
	const path = "/srv/config/auth.json"
	b, e = privatefile.Read(path, 8192)
	if os.IsNotExist(e) {
		return privateWrite(path, cfg)
	}
	if e != nil {
		return e
	}
	var old access.Config
	if e = strictjson.Decode(b, &old); e != nil {
		return e
	}
	a, _ := json.Marshal(old)
	want, _ := json.Marshal(cfg)
	if !bytes.Equal(a, want) {
		return errors.New("switch authentication policy changed across boot")
	}
	return nil
}
func runQuotaSwitchDaemon() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedSwitchConfig(); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "4", "-metrics"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}
func (n *node) switchClients() [2]*switchAPI {
	return [2]*switchAPI{newSwitchAPI("/srv/state/api.sock", n.token), newSwitchAPI("/srv/state/api.sock", n.switchTokenB)}
}
func (c *switchAPI) create(ctx context.Context, key string) (sandbox.Record, error) {
	var r sandbox.Record
	e := c.call(ctx, "POST", "/v1/sandboxes", key, switchGuestSpec(), &r, 201)
	if e == nil && (r.State != sandbox.Ready || r.Backend != "firecracker") {
		e = errors.New("switch real Ready required")
	}
	return r, e
}
func (c *switchAPI) job(ctx context.Context, ref sandbox.Ref, j sandbox.Job) (sandbox.Job, error) {
	var out sandbox.Job
	if !switchRefValid(ref) || !hex32Pattern(j.ID) || j.Ref != ref {
		return out, errors.New("invalid fixed execution lookup binding")
	}
	e := c.call(ctx, "GET", switchPath(ref)+"/executions/"+j.ID, "", nil, &out, 200)
	if e == nil && (out.ID != j.ID || out.Generation != ref.Generation) {
		e = errors.New("execution lookup returned wrong job or generation")
	}
	if e == nil {
		out.Ref = ref // Sandbox ID is carried by the lookup path, not Job JSON.
	}
	return out, e
}
func (c *switchAPI) finish(ctx context.Context, ref sandbox.Ref, j sandbox.Job) (sandbox.Output, error) {
	var out sandbox.Job
	e := waitNode(ctx, func() (bool, error) {
		var e error
		out, e = c.job(ctx, ref, j)
		return e == nil && out.Status != "RUNNING", e
	})
	if e != nil {
		return out.Output, e
	}
	if out.Status != "EXITED" || out.Output.ExitCode != 0 {
		return out.Output, errors.New("fixed switch guest workload failed")
	}
	return out.Output, nil
}
func (c *switchAPI) executeVM(ctx context.Context, ref sandbox.Ref, argv []string) (sandbox.Output, error) {
	var j sandbox.Job
	e := c.call(ctx, "POST", switchPath(ref)+"/exec", "", sandbox.ExecRequest{Generation: ref.Generation, Argv: argv, TimeoutMS: 60000}, &j, 202)
	if e != nil {
		return sandbox.Output{}, e
	}
	if !hex32Pattern(j.ID) || j.Generation != ref.Generation {
		return sandbox.Output{}, errors.New("fixed execution response generation mismatch")
	}
	j.Ref = ref
	return c.finish(ctx, ref, j)
}
func (c *switchAPI) destroyed(ctx context.Context, ref sandbox.Ref) error {
	if !switchRefValid(ref) {
		return errors.New("invalid switch ref")
	}
	if e := waitNode(ctx, func() (bool, error) {
		var r sandbox.Record
		e := c.call(ctx, "GET", switchPath(ref), "", nil, &r, 200)
		return e == nil && r.Ref == ref && r.State == sandbox.Destroyed, e
	}); e != nil {
		return e
	}
	return (&node{}).clean(ref)
}
func (c *switchAPI) remove(ctx context.Context, ref sandbox.Ref) error {
	if e := c.call(ctx, "DELETE", switchPath(ref), "", generationBody(ref), nil, 202); e != nil {
		return e
	}
	return c.destroyed(ctx, ref)
}

func switchReadOwner(ref sandbox.Ref) (clearWindowOwner, []byte, error) {
	var o clearWindowOwner
	if !switchRefValid(ref) {
		return o, nil, errors.New("invalid switch owner ref")
	}
	b, e := privatefile.Read("/srv/state/firecracker/"+ref.ID+ref.Generation+".json", 2048)
	if e != nil {
		return o, nil, e
	}
	if e = strictjson.Decode(b, &o); e != nil {
		return o, nil, e
	}
	if o.Ref != ref || o.Version != 4 || !o.QuotaAttempted || !o.InitializationAttempted || o.UID < 400000 || o.UID >= 400000+switchSlots || o.ProjectID != driverProjectFirst+uint32(o.UID-400000) || !hashPattern.MatchString(o.TemplateID) {
		return o, nil, errors.New("invalid initialized switch owner")
	}
	return o, b, nil
}
func (n *node) switchReady(ref sandbox.Ref, exactAccounting bool) (driverQuotaReceipt, error) {
	var receipt driverQuotaReceipt
	if e := requireNode(); e != nil {
		return receipt, e
	}
	if !n.quotaSwitch || n.process == nil {
		return receipt, errors.New("active switch profile required")
	}
	cfg, e := fixedSwitchConfig()
	if e != nil {
		return receipt, e
	}
	o, _, e := switchReadOwner(ref)
	if e != nil {
		return receipt, e
	}
	if o.TemplateID != n.switchTemplate {
		return receipt, errors.New("switch template identity changed")
	}
	if e = syscallGuestBoundaryWithObserver(cfg, ref, n.process.Process.Pid, false); e != nil {
		return receipt, e
	}
	jail := "/srv/r/j/firecracker/" + ref.ID + ref.Generation
	for _, p := range []string{jail, jail + "/root", jail + "/root/workspace.ext4"} {
		a, e := quotaAttributes(p, nil)
		if e != nil || a.Project != o.ProjectID {
			return receipt, errors.New("switch mutable project mismatch")
		}
		if p != jail+"/root/workspace.ext4" && a.XFlags&quotaInherit == 0 {
			return receipt, errors.New("switch private inheritance lost")
		}
	}
	if e = verifySharedQuotaFiles(jail); e != nil {
		return receipt, e
	}
	q, e := openQuotaFS(false)
	if e != nil {
		return receipt, e
	}
	defer q.file.Close()
	// Only preflight / stable crash checkpoint, NEVER measured switch paths.
	if exactAccounting {
		if e = q.sync(); e != nil {
			return receipt, e
		}
		if e = unix.Syncfs(int(q.file.Fd())); e != nil {
			return receipt, e
		}
	}
	r, e := switchQuotaRead(q, o.ProjectID)
	if e != nil {
		return receipt, e
	}
	if !switchKnown(r) || quotaEmpty(r) || r.Space < 128<<20 || r.Inodes == 0 {
		return receipt, errors.New("Ready switch generation lacks immutable quota")
	}
	receipt = driverQuotaReceipt{Snapshot: true, Phase: "running", Jail: jail, Project: o.ProjectID, Record: r}
	if exactAccounting {
		receipt.NamespaceBlocks, receipt.NamespaceInodes, receipt.Entries, e = driverQuotaTree(jail, true)
		if e != nil {
			return receipt, e
		}
		if e = validateDriverQuotaAccounting(receipt, r, receipt.NamespaceBlocks, receipt.NamespaceInodes, receipt.Entries); e != nil {
			return receipt, e
		}
	}
	return receipt, nil
}
func (n *node) quotaSwitchSetup(ctx context.Context) (map[string]any, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSwitch || n.process != nil {
		return nil, errors.New("fresh switch node required")
	}
	setup, e := n.quotaSnapshotSetup(ctx)
	if e != nil {
		return nil, e
	}
	status, e := n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if !hashPattern.MatchString(status.Active) {
		return nil, errors.New("switch active catalog absent")
	}
	n.switchTemplate = status.Active
	if e = switchAllClear(); e != nil {
		return nil, e
	}
	preflight, e := n.switchPreflight(ctx)
	if e != nil {
		return nil, e
	}
	return map[string]any{"genuine_l1_snapshot_setup": setup, "fixed_node_capacity": switchCapacity, "fixed_tenant_capacity": 3, "fixed_uid_project_slots": switchSlots, "preflight": preflight, "ordinary_production_no_test_observer": true}, nil
}
func (n *node) switchPreflight(ctx context.Context) (map[string]any, error) {
	api := n.switchClients()
	defer api[0].close()
	defer api[1].close()
	refs := []sandbox.Ref{}
	keys := []string{}
	projects := []uint32{}
	for i := 0; i < 4; i++ {
		tenant := 0
		if i == 3 {
			tenant = 1
		}
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		r, e := api[tenant].create(ctx, key)
		if e != nil {
			return nil, e
		}
		refs = append(refs, r.Ref)
		keys = append(keys, key)
		if _, e = n.switchReady(r.Ref, true); e != nil {
			return nil, e
		}
		o, _, e := switchReadOwner(r.Ref)
		if e != nil {
			return nil, e
		}
		for _, p := range projects {
			if p == o.ProjectID {
				return nil, errors.New("four live VMs share private project")
			}
		}
		projects = append(projects, o.ProjectID)
		if i == 2 {
			key, e := randomKey()
			if e != nil {
				return nil, e
			}
			if e = api[0].call(ctx, "POST", "/v1/sandboxes", key, switchGuestSpec(), nil, 429); e != nil {
				return nil, e
			}
		}
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	if e = api[1].call(ctx, "POST", "/v1/sandboxes", key, switchGuestSpec(), nil, 503); e != nil {
		return nil, e
	}
	unauth := newSwitchAPI("/srv/state/api.sock", "")
	defer unauth.close()
	if e = unauth.call(ctx, "GET", switchPath(refs[0]), "", nil, nil, 401); e != nil {
		return nil, e
	}
	if e = api[0].call(ctx, "GET", switchPath(refs[3]), "", nil, nil, 404); e != nil {
		return nil, e
	}
	if _, e = api[1].executeVM(ctx, refs[3], []string{"sh", "-c", "printf beta > switch-marker"}); e != nil {
		return nil, e
	}
	oldBoot, e := api[0].executeVM(ctx, refs[0], []string{"cat", "/proc/sys/kernel/random/boot_id"})
	if e != nil {
		return nil, e
	}
	if _, e = api[0].executeVM(ctx, refs[0], []string{"sh", "-c", "set -e; printf alpha > switch-marker; printf alpha > /tmp/switch-marker; sync"}); e != nil {
		return nil, e
	}
	status, e := n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if e = clearCatalogPins(status, n.switchTemplate, 4); e != nil {
		return nil, e
	}
	for _, name := range []string{"template.mem", "template.state"} {
		var first unix.Stat_t
		for i, ref := range refs {
			var st unix.Stat_t
			if e = unix.Lstat("/srv/r/j/firecracker/"+ref.ID+ref.Generation+"/root/"+name, &st); e != nil {
				return nil, e
			}
			if st.Nlink < 5 {
				return nil, errors.New("four clone shared link count missing")
			}
			if i == 0 {
				first = st
			} else if first.Dev != st.Dev || first.Ino != st.Ino {
				return nil, errors.New("four clones not sharing catalog inode")
			}
		}
	}
	oldOwner, _, e := switchReadOwner(refs[0])
	if e != nil {
		return nil, e
	}
	if e = api[0].remove(ctx, refs[0]); e != nil {
		return nil, e
	}
	q, e := openQuotaFS(false)
	if e != nil {
		return nil, e
	}
	r, e := switchQuotaRead(q, oldOwner.ProjectID)
	q.file.Close()
	if e != nil || !quotaEmpty(r) {
		return nil, errors.New("released switch slot not zero before reuse")
	}
	if e = api[0].call(ctx, "POST", "/v1/sandboxes", keys[0], switchGuestSpec(), nil, 410); e != nil {
		return nil, e
	}
	freshKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	fresh, e := api[0].create(ctx, freshKey)
	if e != nil {
		return nil, e
	}
	if _, e = n.switchReady(fresh.Ref, true); e != nil {
		return nil, e
	}
	freshOwner, _, e := switchReadOwner(fresh.Ref)
	if e != nil {
		return nil, e
	}
	if fresh.Ref == refs[0] || freshOwner.UID != oldOwner.UID || freshOwner.ProjectID != oldOwner.ProjectID {
		return nil, errors.New("controlled clean slot not reused as fresh generation")
	}
	out, e := api[0].executeVM(ctx, fresh.Ref, []string{"sh", "-c", "set -e; test ! -e switch-marker; test ! -e /tmp/switch-marker; cat /proc/sys/kernel/random/boot_id"})
	if e != nil || strings.TrimSpace(out.Stdout) == "" || strings.TrimSpace(out.Stdout) == strings.TrimSpace(oldBoot.Stdout) {
		return nil, errors.New("recycled slot restored assigned guest")
	}
	out, e = api[1].executeVM(ctx, refs[3], []string{"cat", "switch-marker"})
	if e != nil || out.Stdout != "beta" {
		return nil, errors.New("beta affected by alpha recycle")
	}
	refs[0] = fresh.Ref
	for i, ref := range refs {
		tenant := 0
		if i == 3 {
			tenant = 1
		}
		if e = api[tenant].remove(ctx, ref); e != nil {
			return nil, e
		}
	}
	if e = switchAllClear(); e != nil {
		return nil, e
	}
	status, e = n.fixedCatalogStatus(ctx)
	if e != nil {
		return nil, e
	}
	if e = clearCatalogPins(status, n.switchTemplate, 0); e != nil {
		return nil, e
	}
	return map[string]any{"four_simultaneous_real_kvm_quota_guests": true, "four_distinct_private_projects_and_shared_readonly_project_zero_inodes": true, "independent_named_inode_accounting_before_benchmark": true, "alpha_fourth429_with_spare_node_slot_beta_still_executes": true, "node_fifth503_below_beta_tenant_quota": true, "authentication401_and_cross_tenant404": true, "old_key410_resources_absent_quota_zero_before_controlled_slot_reuse": true, "same_uid_project_reused_only_as_fresh_ref_boot_and_workspace": true, "beta_execution_and_data_survived_alpha_recycle": true, "all_eight_projects_zero_and_active_catalog_pins_zero": true}, nil
}

// Keep this parser strict for fixed proc counters; no private identity leaves it.
func switchUint(s string) (uint64, error) { return strconv.ParseUint(strings.TrimSpace(s), 10, 64) }
