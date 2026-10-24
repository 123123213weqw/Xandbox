//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/client"
	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const diagnosticProducers = 80 // Fixed before the first hardware run; NOT changed to hide a missed hold.
const diagnosticRecords = diagnosticProducers + 2
const diagnosticReceipt = "/srv/fixture/diagnostic-receipt.json"

type diagnosticSaved struct {
	Version                                  int
	Mode                                     diagnosticHoldMode
	L1Boot, Config, Authority                string
	Control                                  nodecontrol.State
	Raw                                      sandbox.Ref
	Session                                  session.Result
	RawKey, SessionKey, RawBoot, SessionBoot string
	FailedKeys                               []string
}

func diagnosticMetrics(ctx context.Context) (diagnostics.Stats, error) {
	var out diagnostics.Stats
	if e := requireNode(); e != nil {
		return out, e
	}
	c := newSwitchAPI("/srv/state/metrics.sock", "")
	defer c.close()
	req, e := http.NewRequestWithContext(ctx, "GET", "http://fixture.local/metrics", nil)
	if e != nil {
		return out, e
	}
	r, e := c.http.Do(req)
	if e != nil {
		return out, e
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil || r.StatusCode != 200 || len(b) > 65536 {
		return out, errors.New("bounded diagnostic metrics required")
	}
	names := map[string]*uint64{"xandbox_diagnostics_enqueued_total": &out.Enqueued, "xandbox_diagnostics_dropped_total": &out.Dropped, "xandbox_diagnostics_written_total": &out.Written, "xandbox_diagnostics_write_errors_total": &out.WriteErrors, `xandbox_prepare_failed_total{reason="io"}`: &out.PrepareIO, `xandbox_prepare_failed_total{reason="quota"}`: &out.PrepareQuota, `xandbox_prepare_failed_total{reason="other"}`: &out.PrepareOther}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.Fields(line)
		if len(p) != 2 {
			continue
		}
		ptr, ok := names[p[0]]
		if !ok && p[0] != "xandbox_diagnostics_queued" && p[0] != "xandbox_diagnostics_queue_capacity" {
			continue
		}
		if seen[p[0]] {
			return out, errors.New("duplicate diagnostic metric")
		}
		seen[p[0]] = true
		n, e := strconv.ParseUint(p[1], 10, 64)
		if e != nil || n > 1<<20 {
			return out, errors.New("invalid fixed diagnostic metric")
		}
		if ok {
			*ptr = n
		} else if p[0] == "xandbox_diagnostics_queued" {
			out.Queued = int(n)
		} else {
			out.Capacity = int(n)
		}
	}
	if len(seen) != 9 {
		return out, errors.New("missing diagnostic metrics")
	}
	return out, nil
}
func diagnosticWriterReady(ctx context.Context) (bool, error) {
	c, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	v, e := diagnosticMetrics(c)
	if e != nil {
		return false, nil
	}
	return v.Enqueued == 1 && v.Written == 1 && v.Dropped == 0 && v.WriteErrors == 0 && v.Queued == 0 && v.Capacity == 64, nil
}

// Change ONLY the modes of three INPUT files on this disposable L1 disk.
// securePath rejects any first map iteration before opening/copying a source.
// Bytes, inode, active guests' private copies and all authority remain untouched.
func diagnosticInputModes(refs []sandbox.Ref, bad bool) error {
	if e := requireNode(); e != nil {
		return e
	}
	cfg, e := fixedBudgetConfig()
	if e != nil {
		return e
	}
	assets := []struct{ path, hash, name string }{{cfg.Kernel.Path, cfg.Kernel.SHA256, "kernel"}, {cfg.Initrd.Path, cfg.Initrd.SHA256, "initrd"}, {cfg.Workspace.Path, cfg.Workspace.SHA256, "workspace.ext4"}}
	for _, a := range assets {
		if a.path != "/srv/assets/"+strings.TrimSuffix(a.name, ".ext4") {
			return errors.New("fixed owned input path required")
		}
		info, e := os.Lstat(a.path)
		if e != nil {
			return e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		want := os.FileMode(0444)
		if !bad {
			want = 0666
		}
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != want || st.Uid != 0 || st.Nlink != 1 {
			return errors.New("exact input mode/identity required")
		}
		h, e := fileHash(a.path)
		if e != nil || h != a.hash {
			return errors.New("input bytes changed")
		}
		for _, ref := range refs {
			private, e := os.Stat("/srv/r/j/firecracker/" + ref.ID + ref.Generation + "/root/" + a.name)
			if bad && (e != nil || os.SameFile(info, private)) {
				return errors.New("input must not alias an active guest copy")
			}
		}
	}
	for _, a := range assets {
		mode := os.FileMode(0666)
		if !bad {
			mode = 0444
		}
		if e = os.Chmod(a.path, mode); e != nil {
			return e
		}
	}
	// Input provisioning, NOT authority repair. Sync only after restoration;
	// normal cleanup/receipt may sync the filesystem anyway, not a media-cut test.
	if !bad {
		for _, a := range assets {
			f, e := os.Open(a.path)
			if e != nil {
				return e
			}
			e = f.Sync()
			f.Close()
			if e != nil {
				return e
			}
		}
		d, e := os.Open("/srv/assets")
		if e != nil {
			return e
		}
		defer d.Close()
		return d.Sync()
	}
	return nil
}
func diagnosticAuthority() (string, error) {
	if e := requireNode(); e != nil {
		return "", e
	}
	for _, entry := range []struct{ dir, name string }{{"/srv/state/admission", "state.json"}, {"/srv/state/firecracker", "config.json"}} {
		d, e := os.Open(entry.dir)
		if e != nil {
			return "", e
		}
		names, e := d.Readdirnames(2)
		d.Close()
		if e != nil && !errors.Is(e, io.EOF) {
			return "", e
		}
		if len(names) != 1 || names[0] != entry.name {
			return "", errors.New("unexpected diagnostic control/backend metadata")
		}
	}
	jail, e := os.Open("/srv/r/j/firecracker")
	if e != nil {
		return "", e
	}
	remaining, e := jail.Readdirnames(1)
	jail.Close()
	if e != nil && !errors.Is(e, io.EOF) {
		return "", e
	}
	if len(remaining) != 0 {
		return "", errors.New("private jail remained after diagnostic cleanup")
	}
	h := sha256.New()
	for _, p := range []string{"/srv/state/controller.lock", "/srv/state/admission.identity", "/srv/state/diagnostics/logger.lock", "/srv/state/admission/state.json", "/srv/state/firecracker/config.json", "/srv/config/backend.json", "/srv/config/auth.json"} {
		info, e := os.Lstat(p)
		if e != nil {
			return "", e
		}
		b, e := privatefile.Read(p, 16384)
		if e != nil {
			return "", e
		}
		fmt.Fprintf(h, "%s:%d:%x\n", p, info.Mode(), sha256.Sum256(b))
	}
	for _, dir := range []string{"/srv/state/ledger", "/srv/state/sessions"} {
		d, e := os.Open(dir)
		if e != nil {
			return "", e
		}
		names, e := d.Readdirnames(diagnosticRecords + 1)
		d.Close()
		if e != nil && !errors.Is(e, io.EOF) {
			return "", e
		}
		want := diagnosticRecords
		if dir == "/srv/state/sessions" {
			want = 1
		}
		if len(names) != want {
			return "", errors.New("exact diagnostic authority inventory count required")
		}
		// The digest must not depend on directory enumeration order.
		sort.Strings(names)
		for _, name := range names {
			if len(name) != 37 || !hex32Pattern(name[:32]) || name[32:] != ".json" {
				return "", errors.New("unexpected diagnostic authority name")
			}
			b, e := privatefile.Read(filepath.Join(dir, name), sandbox.MaxLedgerRecordBytes)
			if e != nil {
				return "", e
			}
			if dir == "/srv/state/ledger" {
				var env struct {
					Version int            `json:"version"`
					Record  sandbox.Record `json:"record"`
				}
				if strictjson.Decode(b, &env) != nil || env.Version != 1 || env.Record.ID != name[:32] || env.Record.State != sandbox.Destroyed || env.Record.Backend != "firecracker" || env.Record.TenantID != "nested-fixture" {
					return "", errors.New("every actual ledger record must be durably destroyed")
				}
				if e = budgetAbsent(env.Record.Ref); e != nil {
					return "", e
				}
			}
			fmt.Fprintf(h, "%s/%s:%x\n", dir, name, sha256.Sum256(b))
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func diagnosticRingDigest() (string, error) {
	if e := requireNode(); e != nil {
		return "", e
	}
	b, e := privatefile.Read(diagnosticRingPath, diagnostics.RingBytes)
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%x", sha256.Sum256(b)), nil
}
func (n *node) diagnosticContender(ctx context.Context, o *diagnosticObserver, authority string) error {
	if e := o.bothValid(); e != nil {
		return e
	}
	info, e := os.Lstat("/srv/state/controller.lock")
	if e != nil {
		return e
	}
	ring, e := diagnosticRingDigest()
	if e != nil {
		return e
	}
	cg, e := os.Open(nodeGroup + "/control")
	if e != nil {
		return e
	}
	defer cg.Close()
	short, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(short, "/srv/assets/sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "4", "-max-records", "1024", "-max-sessions", "32", "-metrics")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	e = cmd.Run()
	var ex *exec.ExitError
	if !errors.As(e, &ex) || ex.ExitCode() != 1 || short.Err() != nil || out.String() != "sandboxd: state directory already locked\n" {
		return errors.New("ordinary diagnostic contender must fail original state lock")
	}
	current, e := os.Lstat("/srv/state/controller.lock")
	if e != nil || !os.SameFile(info, current) {
		return errors.New("diagnostic contender changed controller lock")
	}
	after, e := diagnosticAuthority()
	if e != nil || after != authority {
		return errors.New("diagnostic contender changed authority")
	}
	after, e = diagnosticRingDigest()
	if e != nil || after != ring {
		return errors.New("diagnostic contender changed ring")
	}
	for _, p := range []string{"/srv/state/api.sock", "/srv/state/metrics.sock", operatorSocket} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			return errors.New("diagnostic shutdown left listener")
		}
	}
	return o.bothValid()
}
func (n *node) diagnosticCheckpoint(ctx context.Context, mode diagnosticHoldMode) (out map[string]any, err error) {
	if !mode.valid() {
		return nil, errors.New("fixed diagnostic phase required")
	}
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	if e := n.start(ctx); e != nil {
		return nil, e
	}
	if e := n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	o, e := n.startDiagnosticObserved(ctx)
	if e != nil {
		return nil, e
	}
	defer func() {
		if n.process != nil {
			n.process.Process.Kill()
			select {
			case <-n.exited:
				n.process = nil
			case <-time.After(2 * time.Second):
			}
		}
		err = errors.Join(err, o.close())
	}()
	c, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer c.Close()
	view, e := c.Status(ctx)
	if e != nil || !view.Control.AdmissionOpen || view.Control.Committed.Revision != 1 {
		return nil, errors.New("fresh open diagnostic node required")
	}
	before := view.Control.Committed
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	rawKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	raw, e := api.create(ctx, rawKey)
	if e != nil {
		return nil, e
	}
	rawBoot, e := operatorGuest(ctx, n, api, raw.Ref, "raw", nil)
	if e != nil {
		return nil, e
	}
	sessionKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	bound, e := api.openSession(ctx, sessionKey)
	if e != nil {
		return nil, e
	}
	sessionBoot, e := operatorGuest(ctx, n, api, bound.Current, "session", &bound)
	if e != nil || sessionBoot == rawBoot {
		return nil, errors.New("independent diagnostic guest identities required")
	}
	job, e := n.submit(ctx, raw.Ref, []string{"sh", "-c", "i=0; while :; do i=$((i+1)); echo $i > diagnostic-progress.tmp; mv diagnostic-progress.tmp diagnostic-progress; sleep 0.05; done"})
	if e != nil {
		return nil, e
	}
	progress := func() (int, error) {
		v, e := api.executeVM(ctx, raw.Ref, []string{"sh", "-c", "cat diagnostic-progress 2>/dev/null || echo 0"})
		if e != nil {
			return 0, e
		}
		return strconv.Atoi(strings.TrimSpace(v.Stdout))
	}
	first := 0
	if e = waitNode(ctx, func() (bool, error) { var e error; first, e = progress(); return first > 0, e }); e != nil {
		return nil, e
	}
	if e = o.arm(mode); e != nil {
		return nil, e
	}
	refs := []sandbox.Ref{raw.Ref, bound.Current}
	if e = diagnosticInputModes(refs, true); e != nil {
		return nil, e
	}
	// Modes restored only on the owned INPUT leaves, even if the test fails.
	restored := false
	defer func() {
		if !restored {
			err = errors.Join(err, diagnosticInputModes(nil, false))
		}
	}()
	keys := make([]string, 0, diagnosticProducers)
	for i := 0; i < diagnosticProducers; i++ {
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		keys = append(keys, key)
		if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 500); e != nil {
			return nil, e
		}
		if i == 0 {
			select {
			case <-o.held:
			case <-o.done:
				return nil, errors.Join(errors.New("diagnostic observer ended before hold"), o.snapshot().Err)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if e = o.heldValid(); e != nil {
			return nil, e
		}
		if e = operatorIdle(ctx, c, 2, i+3); e != nil {
			return nil, e
		}
	}
	stats, e := diagnosticMetrics(ctx)
	if e != nil {
		return nil, e
	}
	if e = diagnosticPressure(stats); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { v, e := progress(); return v > first, e }); e != nil {
		return nil, e
	}
	current, e := n.job(ctx, raw.Ref, job)
	if e != nil || current.Status != "RUNNING" {
		return nil, errors.New("accepted guest stopped during held diagnostic writer")
	}
	value, e := api.sessionExec(ctx, bound, []string{"cat", "operator-marker"})
	if e != nil || value.Stdout != "session" {
		return nil, errors.New("session route changed during diagnostic pressure")
	}
	began := time.Now()
	if e = api.call(ctx, "DELETE", switchPath(raw.Ref), "", generationBody(raw.Ref), nil, 202); e != nil {
		return nil, e
	}
	var revoked struct {
		Revoked   bool `json:"admission_revoked"`
		Durable   bool `json:"durable"`
		Stopped   bool `json:"stop_confirmed"`
		Reclaimed bool `json:"reclamation_confirmed"`
	}
	if e = api.call(ctx, "POST", "/v1/sessions/"+bound.ID+"/revoke", "", map[string]any{"expected_revision": bound.Revision}, &revoked, 200); e != nil {
		return nil, e
	}
	if !revoked.Revoked || revoked.Durable || revoked.Stopped || revoked.Reclaimed {
		return nil, errors.New("session admission revoke is not Stop/GC acknowledgment")
	}
	if e = waitNode(ctx, func() (bool, error) {
		for _, ref := range refs {
			empty, e := nodePrepareGroupEmpty(ref)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return false, e
			}
			if !empty {
				return false, nil
			}
		}
		return true, o.heldValid()
	}); e != nil {
		return nil, e
	}
	stopMS := switchMS(began)
	for _, ref := range refs {
		if e = budgetDestroyed(ctx, api, ref); e != nil {
			return nil, e
		}
		if e = shutdownDurable(ref); e != nil {
			return nil, e
		}
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, c, 0, diagnosticRecords); e != nil {
		return nil, e
	}
	reclaimMS := switchMS(began)
	if e = o.heldValid(); e != nil {
		return nil, e
	}
	if e = diagnosticInputModes(nil, false); e != nil {
		return nil, e
	}
	restored = true
	if e = waitNode(ctx, func() (bool, error) {
		b, e := operatorSessionBytes(bound.ID)
		if e != nil {
			return false, nil
		}
		var env struct {
			Version int            `json:"version"`
			Record  session.Record `json:"record"`
		}
		if strictjson.Decode(b, &env) != nil {
			return false, errors.New("invalid ordinary session journal")
		}
		return env.Version == 1 && env.Record.State == session.Closed && env.Record.Current == bound.Current, nil
	}); e != nil {
		return nil, e
	}
	if _, e = diagnosticAuthority(); e != nil {
		return nil, e
	}
	if e = o.signal(); e != nil {
		return nil, e
	}
	if e = n.process.Process.Signal(syscall.SIGTERM); e != nil {
		return nil, e
	}
	select {
	case <-o.exitHeld:
	case <-o.done:
		return nil, errors.Join(errors.New("diagnostic observer ended before exit"), o.snapshot().Err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = o.bothValid(); e != nil {
		return nil, e
	}
	// Session.Close legitimately rewrites CLOSED.UpdatedAt during run's defers.
	// Snapshot the stable namespace only AFTER actual EXIT_GROUP entry, before
	// the contender: comparing against a pre-SIGTERM digest falsely attributes
	// ordinary shutdown writes to that separate refused process.
	authority, e := diagnosticAuthority()
	if e != nil {
		return nil, e
	}
	if e = n.diagnosticContender(ctx, o, authority); e != nil {
		return nil, e
	}
	snap := o.snapshot()
	o.continueExit <- struct{}{}
	select {
	case e = <-n.exited:
		var ex *exec.ExitError
		if !errors.As(e, &ex) || ex.ExitCode() != 1 {
			return nil, errors.New("diagnostic ordinary daemon did not really exit1")
		}
		n.process = nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = waitNode(ctx, func() (bool, error) { return o.snapshot().ExitContinued == 1, o.snapshot().Err }); e != nil {
		return nil, e
	}
	if e = o.invalidAfterReap(); e != nil {
		return nil, e
	}
	if e = o.close(); e != nil {
		return nil, e
	}
	log, e := privatefile.Read(diagnosticControllerLog, 1)
	if e != nil || len(log) != 0 {
		return nil, errors.New("ordinary logger fell back to inherited output")
	}
	n.api.Close()
	n.api = client.NewWithToken("/srv/state/api.sock", n.token)
	saved := diagnosticSaved{Version: 1, Mode: mode, L1Boot: n.boot, Control: before, Authority: authority, Raw: raw.Ref, Session: bound, RawKey: rawKey, SessionKey: sessionKey, RawBoot: rawBoot, SessionBoot: sessionBoot, FailedKeys: keys}
	saved.Config, e = fileHash("/srv/config/backend.json")
	if e != nil {
		return nil, e
	}
	if e = privateWrite(diagnosticReceipt, saved); e != nil {
		return nil, e
	}
	return map[string]any{"real_nested_kvm": true, "fixed_closed_ring_phase_and_original_inode_checked": true, "actual_ring_fsync_held_without_target_reply": true, "real_failed_prepare_producers_with_only_owned_input_mode_fault": true, "queue64_full_drops_explicit_no_producer_storage_wait": true, "accepted_raw_job_progress_and_session_route_preserved": true, "both_guests_stopped_durable_gc_and_quota0_while_ring_fsync_held": true, "actual_sigterm_close_budget_then_exit_group1": true, "same_ordinary_contender_original_lock_refused_no_authority_or_ring_change": true, "actual_exit1_reaped_then_ids_enoent_listener_open": true, "only_exit_group_continued_no_ring_reply": true, "inputs_restored_bytes_unchanged_no_authority_repair": true, "no_inherited_output_fallback": true, "mode": string(mode), "producer_failures": diagnosticProducers, "queued": 64, "dropped": 15, "observed_sequence_before_cold": mode.observed(), "ring_fsync_entries": snap.RingEntries, "data_fsync_continue_submissions": snap.DataContinued, "target_reply_submissions": 0, "exit_group_continue_submissions": 1, "other_continue_submissions": snap.OtherContinued, "other_continue_while_held": snap.OtherWhileHeld, "hold_bound_ms": 20000, "delete_to_execution_empty_observed_ms": stopMS, "delete_to_private_quota0_observed_ms": reclaimMS, "signal_to_exit_group_entry_observed_ms": float64(snap.ExitAt.Sub(snap.SignalAt)) / float64(time.Millisecond), "filesystem_d_or_physical_media_fault_claim": false, "durable_audit_or_production_slo_claim": false}, nil
}
func (n *node) diagnosticRecover(ctx context.Context, mode diagnosticHoldMode) (map[string]any, error) {
	if !mode.valid() {
		return nil, errors.New("fixed diagnostic recovery phase required")
	}
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	b, e := privatefile.Read(diagnosticReceipt, 16384)
	if e != nil {
		return nil, e
	}
	var saved diagnosticSaved
	if strictjson.Decode(b, &saved) != nil || saved.Version != 1 || saved.Mode != mode || saved.L1Boot == n.boot || !switchRefValid(saved.Raw) || !switchRefValid(saved.Session.Current) || !(len(saved.Config) == 64 && strings.Trim(saved.Config, "0123456789abcdef") == "") || len(saved.FailedKeys) != diagnosticProducers {
		return nil, errors.New("fixed private diagnostic cold receipt required")
	}
	if e = validateDiagnosticSaved(saved, mode, n.boot); e != nil {
		return nil, e
	}
	cfg, e := fixedBudgetConfig()
	if e != nil {
		return nil, e
	}
	for _, a := range []struct{ p, h string }{{cfg.Kernel.Path, cfg.Kernel.SHA256}, {cfg.Initrd.Path, cfg.Initrd.SHA256}, {cfg.Workspace.Path, cfg.Workspace.SHA256}} {
		info, e := os.Lstat(a.p)
		if e != nil || info.Mode().Perm() != 0444 {
			return nil, errors.New("cold input modes not restored")
		}
		h, e := fileHash(a.p)
		if e != nil || h != a.h {
			return nil, errors.New("cold input bytes changed")
		}
	}
	hash, e := fileHash("/srv/config/backend.json")
	if e != nil || hash != saved.Config {
		return nil, errors.New("diagnostic cold config changed")
	}
	authority, e := diagnosticAuthority()
	if e != nil || authority != saved.Authority {
		return nil, errors.New("diagnostic cold authority changed")
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	prior, e := diagnostics.Read(filepath.Dir(diagnosticRingPath))
	if e != nil {
		return nil, e
	}
	if prior.ObservedSequence != 4 && (mode != diagnosticHeader || prior.ObservedSequence != 5) {
		return nil, errors.New("cold observed prefix outside unACKed phase possibilities")
	}
	if e = diagnosticPrefix(prior, prior.ObservedSequence); e != nil {
		return nil, e
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	c, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer c.Close()
	view, e := c.Status(ctx)
	if e != nil || view.Control.Committed != saved.Control || !view.Control.AdmissionOpen {
		return nil, errors.New("ordinary diagnostic cold authority mismatch")
	}
	api := newSwitchAPI("/srv/state/api.sock", n.token)
	defer api.close()
	for _, ref := range []sandbox.Ref{saved.Raw, saved.Session.Current} {
		if e = budgetDestroyed(ctx, api, ref); e != nil {
			return nil, e
		}
	}
	for _, key := range append([]string{saved.RawKey}, saved.FailedKeys...) {
		if e = api.call(ctx, "POST", "/v1/sandboxes", key, nodeSpec(), nil, 410); e != nil {
			return nil, e
		}
	}
	if e = api.call(ctx, "POST", "/v1/sessions", saved.SessionKey, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	if e = api.call(ctx, "POST", "/v1/sessions/"+saved.Session.ID+"/exec", "", map[string]any{"revision": saved.Session.Revision, "argv": []string{"true"}, "timeout_ms": 5000}, nil, 410); e != nil {
		return nil, e
	}
	key, e := randomKey()
	if e != nil {
		return nil, e
	}
	fresh, e := api.create(ctx, key)
	if e != nil {
		return nil, e
	}
	boot, e := operatorGuest(ctx, n, api, fresh.Ref, "cold", nil)
	if e != nil || boot == saved.RawBoot || boot == saved.SessionBoot {
		return nil, errors.New("fresh diagnostic cold guest identity mismatch")
	}
	if e = api.call(ctx, "DELETE", switchPath(fresh.Ref), "", generationBody(fresh.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, api, fresh.Ref); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, c, 0, diagnosticRecords+1); e != nil {
		return nil, e
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	after, e := diagnostics.Read(filepath.Dir(diagnosticRingPath))
	if e != nil || after.ObservedSequence != prior.ObservedSequence+3 || after.Records[len(after.Records)-1].Event.Kind != diagnostics.CollectorClosed {
		return nil, errors.New("ordinary cold writer did not continue validated ring")
	}
	for _, p := range []string{nodeBudgetInstances, nodeGroup + "/control", nodeGroup} {
		if e = os.Remove(p); e != nil {
			return nil, e
		}
	}
	return map[string]any{"mode": string(mode), "l1_boot_changed_original_disk_before_daemon_checked": true, "cold_valid_prefix_not_a_durability_ack": true, "ordinary_unfiltered_writer_continues_ring_no_reset_or_repair": true, "old_raw_session_and_all_failed_keys410_no_route_resurrection": true, "fresh_real_guest_uid_boot_clean_workspace_and_full_gc": true, "all_projects_zero_pools_idle_daemon_reaped_node_subtree_removed": true, "input_bytes_modes_and_authority_not_repaired": true, "observed_sequence_before_start": prior.ObservedSequence, "retained_destroyed_records": diagnosticRecords + 1}, nil
}

func validateDiagnosticSaved(s diagnosticSaved, m diagnosticHoldMode, boot string) error {
	if !m.valid() || s.Version != 1 || s.Mode != m || !switchUUID(s.L1Boot) || s.L1Boot == boot || !switchUUID(s.RawBoot) || !switchUUID(s.SessionBoot) || s.RawBoot == s.SessionBoot || !switchRefValid(s.Raw) || !switchRefValid(s.Session.Current) || s.Raw.ID == s.Session.Current.ID || !hex32Pattern(s.Session.ID) || s.Session.Revision != 1 || s.Control.Version != 1 || s.Control.Mode != nodecontrol.ModeOpen || s.Control.Revision != 1 || !hex32Pattern(s.Control.Epoch) || s.Control.LastRequestID != "" || s.Control.LastExpectedRevision != 0 || len(s.FailedKeys) != diagnosticProducers {
		return errors.New("invalid fixed diagnostic receipt identity")
	}
	for _, v := range []string{s.Config, s.Authority} {
		if len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "" {
			return errors.New("invalid diagnostic receipt hash")
		}
	}
	seen := map[string]bool{}
	for _, v := range append([]string{s.RawKey, s.SessionKey}, s.FailedKeys...) {
		if len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "" || seen[v] {
			return errors.New("invalid/duplicate diagnostic receipt key")
		}
		seen[v] = true
	}
	return nil
}

func diagnosticPressure(s diagnostics.Stats) error {
	if s.Capacity != 64 || s.Queued != 64 || s.Enqueued != 66 || s.Dropped != 15 || s.Written != 1 || s.WriteErrors != 0 || s.PrepareIO != 0 || s.PrepareQuota != 0 || s.PrepareOther != diagnosticProducers {
		return fmt.Errorf("fixed diagnostic queue pressure mismatch %+v", s)
	}
	return nil
}
