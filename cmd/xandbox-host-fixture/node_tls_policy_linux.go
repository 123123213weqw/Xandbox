//go:build linux && xandbox_host_fixture

package main

// TEST ONLY own-L1 reload commit windows. The fixture provisions operator
// INPUT, observes production policy, and never rewrites authority records.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type tlsPolicySaved struct {
	Version                                                         int
	Mode                                                            tlsPolicyMode
	L1Boot, Config, Auth, Policy, Identity, Lock, CA, IngressConfig string
	Before                                                          nodecontrol.State
	Baseline, Attempted, Observed                                   tlsPolicyRecord
	Raw                                                             sandbox.Ref
	Binding                                                         session.Result
	RawKey, SessionKey, AlphaOld, AlphaNew, BetaExternal            string
	Boots                                                           [2]string
}

func tlsPolicyExpectedDisk(m tlsPolicyMode, before, next tlsPolicyRecord) tlsPolicyRecord {
	if m == tlsPolicyPre {
		return before
	}
	return next
}
func validateTLSPolicySaved(s tlsPolicySaved, boot string) error {
	if s.Version != 1 || !s.Mode.valid() || !switchUUID(s.L1Boot) || s.L1Boot == boot || !switchRefValid(s.Raw) || !switchRefValid(s.Binding.Current) || s.Raw == s.Binding.Current || !hex32Pattern(s.Binding.ID) || s.Binding.Revision != 1 || s.Binding.Previous != (sandbox.Ref{}) {
		return errors.New("invalid private policy cold receipt")
	}
	for _, h := range []string{s.Config, s.Auth, s.Policy, s.Identity, s.Lock, s.CA, s.IngressConfig, s.Baseline.Digest, s.Attempted.Digest} {
		if !hashPattern.MatchString(h) {
			return errors.New("invalid private policy hash")
		}
	}
	if s.Baseline.Version != 1 || s.Baseline.Revision != 1 || s.Attempted.Version != 1 || s.Attempted.Revision != 2 || s.Baseline.Digest == s.Attempted.Digest || s.Observed != tlsPolicyExpectedDisk(s.Mode, s.Baseline, s.Attempted) {
		return errors.New("invalid pre/post policy namespace")
	}
	seen := map[string]bool{}
	for _, key := range []string{s.RawKey, s.SessionKey, s.AlphaOld, s.AlphaNew, s.BetaExternal} {
		if !hashPattern.MatchString(key) || seen[key] {
			return errors.New("aliased private policy keys")
		}
		seen[key] = true
	}
	if !switchUUID(s.Boots[0]) || !switchUUID(s.Boots[1]) || s.Boots[0] == s.Boots[1] {
		return errors.New("independent policy guests required")
	}
	b := s.Before
	if b.Version != 1 || b.Mode != nodecontrol.ModeOpen || b.Revision != 1 || !hex32Pattern(b.Epoch) || b.LastRequestID != "" || b.LastExpectedRevision != 0 {
		return errors.New("unexpected ordinary policy cold authority")
	}
	return nil
}
func tlsPolicyRequireKilled(p *gatewayProcess) error {
	select {
	case <-p.done:
	default:
		return errors.New("known gateway not reaped")
	}
	if p.cmd.ProcessState == nil {
		return errors.New("gateway missing actual wait status")
	}
	st, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !st.Signaled() || st.Signal() != syscall.SIGKILL {
		return errors.New("gateway not actually killed at held syscall")
	}
	return nil
}
func (n *node) nodeTLSPolicyCheckpoint(ctx context.Context, m tlsPolicyMode) (out map[string]any, err error) {
	if !m.valid() {
		return nil, errors.New("fixed gateway policy phase required")
	}
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	if e := gatewayLoopback(); e != nil {
		return nil, e
	}
	if _, e := os.Lstat(gatewayDir); !os.IsNotExist(e) {
		return nil, errors.New("fresh TLS policy fixture required")
	}
	betaBackend, e := randomKey()
	if e != nil {
		return nil, e
	}
	alphaOld, e := randomKey()
	if e != nil {
		return nil, e
	}
	alphaNew, e := randomKey()
	if e != nil {
		return nil, e
	}
	betaExternal, e := randomKey()
	if e != nil {
		return nil, e
	}
	auth := access.Config{Version: 1, Keys: []access.Key{{TokenSHA256: gatewayHashToken(n.token), TenantID: "nested-fixture", MaxInstances: 2}, {TokenSHA256: gatewayHashToken(betaBackend), TenantID: gatewayBeta, MaxInstances: 2}}}
	if e = privateWrite("/srv/config/auth.json", auth); e != nil {
		return nil, e
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	ordinaryPID := n.process.Process.Pid
	ordinaryStart, e := processStart(ordinaryPID)
	if e != nil {
		return nil, e
	}
	control, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer control.Close()
	initial, e := control.Status(ctx)
	if e != nil || !initial.Control.AdmissionOpen || initial.Control.Committed.Revision != 1 || initial.ResourceObservation.Records != 0 {
		return nil, errors.New("fresh ordinary policy controller required")
	}
	cfg, ca, e := gatewayPrepare(n.token, betaBackend, alphaOld, betaExternal)
	if e != nil {
		return nil, e
	}
	baseline, e := tlsPolicyExpected(cfg)
	if e != nil {
		return nil, e
	}
	alpha, trace, e := gatewayAPI(ca, alphaOld)
	if e != nil {
		return nil, e
	}
	defer alpha.close()
	beta, _, e := gatewayAPI(ca, betaExternal)
	if e != nil {
		return nil, e
	}
	defer beta.close()
	p, o, e := startTLSPolicyGateway(ctx)
	if e != nil {
		return nil, e
	}
	defer func() { p.kill(); err = errors.Join(err, o.close()) }()
	if e = p.ready(ctx, alpha); e != nil {
		return nil, e
	}
	if e = gatewayRoles(p); e != nil {
		return nil, e
	}
	if trace.serial.Load() != 1 {
		return nil, errors.New("policy initial leaf not verified")
	}
	if disk, e := tlsPolicyRead(); e != nil || disk != baseline {
		return nil, errors.New("initial production policy digest differs from input")
	}
	rawKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	raw, e := alpha.create(ctx, rawKey)
	if e != nil {
		return nil, e
	}
	rawBoot, e := operatorGuest(ctx, n, alpha, raw.Ref, "raw", nil)
	if e != nil {
		return nil, e
	}
	sessionKey, e := randomKey()
	if e != nil {
		return nil, e
	}
	bound, e := beta.openSession(ctx, sessionKey)
	if e != nil {
		return nil, e
	}
	sessionBoot, e := operatorGuest(ctx, n, beta, bound.Current, "session", &bound)
	if e != nil || sessionBoot == rawBoot {
		return nil, errors.New("independent policy guest boots required")
	}
	if e = alpha.call(ctx, "GET", switchPath(bound.Current), "", nil, nil, 404); e != nil {
		return nil, e
	}
	if e = beta.call(ctx, "GET", switchPath(raw.Ref), "", nil, nil, 404); e != nil {
		return nil, e
	}
	// Explicit private operator clients only for observing existing work/cleanup
	// once ingress is withdrawn. They are never a tenant transport fallback.
	directAlpha := newSwitchAPI("/srv/state/api.sock", n.token)
	defer directAlpha.close()
	directBeta := newSwitchAPI("/srv/state/api.sock", betaBackend)
	defer directBeta.close()
	var busy sandbox.Job
	e = alpha.call(ctx, "POST", switchPath(raw.Ref)+"/exec", "", sandbox.ExecRequest{Generation: raw.Ref.Generation, Argv: []string{"sh", "-c", "i=0; while :; do i=$((i+1)); printf '%s\\n' \"$i\" > policy-progress.tmp; mv policy-progress.tmp policy-progress; sleep 0.05; done"}, TimeoutMS: 60000}, &busy, 202)
	if e != nil || !hex32Pattern(busy.ID) || busy.Generation != raw.Ref.Generation {
		return nil, errors.New("actual TLS busy execution was not admitted")
	}
	progress := func() (int, error) {
		v, e := directAlpha.executeVM(ctx, raw.Ref, []string{"sh", "-c", "cat policy-progress 2>/dev/null || echo 0"})
		if e != nil {
			return 0, e
		}
		return strconv.Atoi(strings.TrimSpace(v.Stdout))
	}
	first := 0
	if e = waitNode(ctx, func() (bool, error) { var e error; first, e = progress(); return first > 0, e }); e != nil {
		return nil, e
	}
	// Warm the current external TLS AND private upstream keepalive before root
	// stops processing new broker dial requests. New-key401 is local to child.
	if e = alpha.call(ctx, "GET", "/healthz", "", nil, nil, 200); e != nil {
		return nil, e
	}
	cfg.PolicyRevision = 2
	cfg.Keys = append([]gateway.ClientKey(nil), cfg.Keys...)
	cfg.Keys[0].TokenSHA256 = gatewayHashToken(alphaNew)
	cfg.CertificateFile = gatewayDir + "/server2.pem"
	cfg.PrivateKeyFile = gatewayDir + "/server2.key"
	attempted, e := tlsPolicyExpected(cfg)
	if e != nil {
		return nil, e
	}
	if e = privateWrite(gatewayConfig, cfg); e != nil {
		return nil, e
	}
	if e = o.arm(m, baseline, attempted); e != nil {
		return nil, e
	}
	if e = p.cmd.Process.Signal(syscall.SIGHUP); e != nil {
		return nil, e
	}
	select {
	case <-o.held:
	case <-o.done:
		return nil, errors.Join(errors.New("gateway observer ended before target"), o.snapshot().Err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e = o.heldValid(); e != nil {
		return nil, e
	}
	// No new snapshot exists in the post-commit MEMFD_CREATE hold, and no policy
	// was published in either phase. Current old auth/leaf remains until timeout.
	if e = alpha.call(ctx, "GET", "/healthz", "", nil, nil, 200); e != nil || trace.serial.Load() != 1 {
		return nil, errors.New("unpublished reload changed old TLS policy")
	}
	nextAPI, _, e := gatewayAPI(ca, alphaNew)
	if e != nil {
		return nil, e
	}
	defer nextAPI.close()
	if e = nextAPI.call(ctx, "GET", "/healthz", "", nil, nil, 401); e != nil {
		return nil, errors.New("new credential published before held boundary")
	}
	waitCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	e = waitNode(waitCtx, func() (bool, error) {
		if e := o.heldValid(); e != nil {
			return false, e
		}
		select {
		case <-p.done:
			return false, errors.New("root exited instead of remaining held")
		default:
		}
		_, e := os.Stat(fmt.Sprintf("/proc/%d", p.child))
		return os.IsNotExist(e), nil
	})
	cancel()
	if e != nil {
		return nil, e
	}
	watchdogMS := switchMS(o.snapshot().HeldAt)
	if e = gatewayAbsentListener(); e != nil {
		return nil, e
	}
	alpha.close()
	short, stop := context.WithTimeout(ctx, time.Second)
	unavailable := alpha.call(short, "GET", "/healthz", "", nil, nil, 200)
	stop()
	if unavailable == nil {
		return nil, errors.New("TLS ingress remained after watchdog")
	}
	if e = o.heldValid(); e != nil {
		return nil, e
	}
	if e = gatewayDaemonSame(n, ordinaryPID, ordinaryStart); e != nil {
		return nil, e
	}
	var running sandbox.Job
	if e = directAlpha.call(ctx, "GET", switchPath(raw.Ref)+"/executions/"+busy.ID, "", nil, &running, 200); e != nil || running.Status != "RUNNING" {
		return nil, errors.New("accepted guest job stopped with ingress")
	}
	second, e := progress()
	if e != nil || second <= first {
		return nil, errors.New("guest writer did not progress across ingress watchdog")
	}
	if v, e := directBeta.sessionExec(ctx, bound, []string{"sh", "-c", "test \"$(cat operator-marker)\" = session; id -u; cat /proc/sys/kernel/random/boot_id"}); e != nil {
		return nil, e
	} else if boot, e := switchGuestIdentity(v); e != nil || boot != sessionBoot {
		return nil, errors.New("existing session changed with ingress")
	}
	if e = o.heldValid(); e != nil {
		return nil, e
	}
	held := o.snapshot()
	p.kill()
	if e = tlsPolicyRequireKilled(p); e != nil {
		return nil, e
	}
	if e = o.invalidAfterReap(); e != nil {
		return nil, e
	}
	if e = gatewayGone(p); e != nil {
		return nil, e
	}
	if e = o.close(); e != nil {
		return nil, e
	}
	// These ordinary cleanup operations may sync the filesystem. We do NOT claim
	// an unsynced-temp media cut; the held pre-rename FSYNC never received a reply.
	began := time.Now()
	owner, _, e := budgetOwner(raw.Ref)
	if e != nil {
		return nil, e
	}
	if e = directAlpha.call(ctx, "DELETE", switchPath(raw.Ref), "", generationBody(raw.Ref), nil, 202); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) {
		empty, e := nodePrepareGroupEmpty(raw.Ref)
		if os.IsNotExist(e) {
			return true, nil
		}
		return empty, e
	}); e != nil {
		return nil, e
	}
	stopMS := switchMS(began)
	if e = budgetDestroyed(ctx, directAlpha, raw.Ref); e != nil {
		return nil, e
	}
	q, e := driverQuotaRead(owner.ProjectID)
	if e != nil || !quotaEmpty(q) {
		return nil, errors.New("policy raw private quota not cleared")
	}
	reclaimMS := switchMS(began)
	if e = directBeta.revoke(ctx, bound); e != nil {
		return nil, e
	}
	if e = budgetDestroyed(ctx, directBeta, bound.Current); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	if e = operatorIdle(ctx, control, 0, 2); e != nil {
		return nil, e
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	observed, e := tlsPolicyRead()
	if e != nil || observed != tlsPolicyExpectedDisk(m, baseline, attempted) {
		return nil, errors.New("held policy record changed after exact root death")
	}
	saved := tlsPolicySaved{Version: 1, Mode: m, L1Boot: n.boot, Before: initial.Control.Committed, Baseline: baseline, Attempted: attempted, Observed: observed, Raw: raw.Ref, Binding: bound, RawKey: rawKey, SessionKey: sessionKey, AlphaOld: alphaOld, AlphaNew: alphaNew, BetaExternal: betaExternal, Boots: [2]string{rawBoot, sessionBoot}}
	for _, v := range []struct {
		path string
		out  *string
	}{{"/srv/config/backend.json", &saved.Config}, {"/srv/config/auth.json", &saved.Auth}, {tlsPolicyRoot + "/policy.json", &saved.Policy}, {tlsPolicyRoot + "/policy.identity", &saved.Identity}, {tlsPolicyRoot + "/gateway.lock", &saved.Lock}, {gatewayDir + "/ca.pem", &saved.CA}, {gatewayConfig, &saved.IngressConfig}} {
		h, e := fileHash(v.path)
		if e != nil {
			return nil, e
		}
		*v.out = h
	}
	if e = privateWrite(tlsPolicyReceipt, saved); e != nil {
		return nil, e
	}
	return map[string]any{"real_tls13_two_tenant_kvm_uid_boot_workspace_and_cross404": true, "exact_gateway_elf_tgid_incarnation_nodecontrol_and_child_privileges_checked": true, "operator_config2_input_synced_no_policy_authority_fixture_patch": true, "fixed_reload_target_held_no_reply_and_old_key_leaf1_new_key401_before_watchdog": true, "child_heartbeat_watchdog_closes_tls_while_root_notification_valid": true, "ordinary_controller_same_incarnation_busy_guest_progress_and_session_continue": true, "root_actually_sigkill_reaped_target_enoent_on_still_open_listener": true, "independent_execution_stop_private_destroy_quota0_and_all_reaped_before_cold": true, "cold_receipt_fsynced_after_real_ordinary_cleanup_no_claim_unsynced_media_cut": true, "file_fsync_entries": held.FileEntries, "directory_fsync_entries": held.DirEntries, "policy_memfd_entries": held.MemfdEntries, "target_continue_or_errno_replies": 0, "other_continue_submissions": held.Continued, "other_continue_while_held": held.OtherWhileHeld, "policy_revision_before_cold": int(observed.Revision), "hold_bound_ms": int(tlsPolicyHoldMax / time.Millisecond), "held_to_child_gone_observed_ms": watchdogMS, "delete_to_execution_empty_observed_ms": stopMS, "delete_to_durable_private_quota0_observed_ms": reclaimMS, "filesystem_d_or_physical_media_fault_claim": false, "production_slo_or_all_policy_windows_claim": false}, nil
}
func (n *node) nodeTLSPolicyRecover(ctx context.Context, m tlsPolicyMode) (map[string]any, error) {
	if !m.valid() {
		return nil, errors.New("fixed gateway policy recovery phase required")
	}
	if e := n.operatorProfile(); e != nil {
		return nil, e
	}
	if e := gatewayLoopback(); e != nil {
		return nil, e
	}
	b, e := privatefile.Read(tlsPolicyReceipt, 32768)
	if e != nil {
		return nil, e
	}
	var s tlsPolicySaved
	if strictjson.Decode(b, &s) != nil || validateTLSPolicySaved(s, n.boot) != nil || s.Mode != m {
		return nil, errors.New("invalid policy cold receipt")
	}
	for _, v := range []struct{ path, hash string }{{"/srv/config/backend.json", s.Config}, {"/srv/config/auth.json", s.Auth}, {tlsPolicyRoot + "/policy.json", s.Policy}, {tlsPolicyRoot + "/policy.identity", s.Identity}, {tlsPolicyRoot + "/gateway.lock", s.Lock}, {gatewayDir + "/ca.pem", s.CA}, {gatewayConfig, s.IngressConfig}} {
		h, e := fileHash(v.path)
		if e != nil || h != v.hash {
			return nil, errors.New("original policy cold disk changed")
		}
	}
	if disk, e := tlsPolicyRead(); e != nil || disk != s.Observed {
		return nil, errors.New("cold actual policy namespace differs")
	}
	if disk, e := operatorState(); e != nil || disk != s.Before {
		return nil, errors.New("cold ordinary authority changed")
	}
	if e = gatewayColdRecord(s.Raw, "nested-fixture"); e != nil {
		return nil, e
	}
	if e = gatewayColdRecord(s.Binding.Current, gatewayBeta); e != nil {
		return nil, e
	}
	if e = driverQuotaAllClear(); e != nil {
		return nil, e
	}
	cfg, e := gatewayConfigRead()
	if e != nil {
		return nil, e
	}
	attempted, e := tlsPolicyExpected(cfg)
	if e != nil || attempted != s.Attempted {
		return nil, errors.New("cold current operator config does not match revision2")
	}
	original := cfg
	original.PolicyRevision = 1
	original.Keys = append([]gateway.ClientKey(nil), cfg.Keys...)
	original.Keys[0].TokenSHA256 = gatewayHashToken(s.AlphaOld)
	original.CertificateFile = gatewayDir + "/server1.pem"
	original.PrivateKeyFile = gatewayDir + "/server1.key"
	before, e := tlsPolicyExpected(original)
	if e != nil || before != s.Baseline {
		return nil, errors.New("cold baseline input differs")
	}
	if e = n.start(ctx); e != nil {
		return nil, e
	}
	control, e := nodecontrol.NewClient("/srv/state")
	if e != nil {
		return nil, e
	}
	defer control.Close()
	view, e := control.Status(ctx)
	if e != nil || view.Control.Committed != s.Before || !view.Control.AdmissionOpen || view.Control.PendingSessionReservations != 0 {
		return nil, errors.New("ordinary cold policy startup mismatch")
	}
	if e = operatorIdle(ctx, control, 0, 2); e != nil {
		return nil, e
	}
	// Only operator INPUT is changed for the deliberate old-config attempt. The
	// post-commit journal itself remains unmodified and must refuse revision1.
	if m == tlsPolicyPost {
		if e = privateWrite(gatewayConfig, original); e != nil {
			return nil, e
		}
		denied, e := startGateway(ctx, 1)
		if e != nil {
			return nil, e
		}
		defer denied.kill()
		if e = denied.wait(ctx, 1); e != nil {
			return nil, e
		}
		if e = gatewayGone(denied); e != nil {
			return nil, e
		}
		if e = gatewayAbsentListener(); e != nil {
			return nil, e
		}
		if h, e := fileHash(tlsPolicyRoot + "/policy.json"); e != nil || h != s.Policy {
			return nil, errors.New("old config refusal changed durable revision2")
		}
		if e = privateWrite(gatewayConfig, cfg); e != nil {
			return nil, e
		}
	}
	ca, e := privatefile.Read(gatewayDir+"/ca.pem", 65536)
	if e != nil {
		return nil, e
	}
	api, trace, e := gatewayAPI(ca, s.AlphaNew)
	if e != nil {
		return nil, e
	}
	defer api.close()
	old, _, e := gatewayAPI(ca, s.AlphaOld)
	if e != nil {
		return nil, e
	}
	defer old.close()
	beta, _, e := gatewayAPI(ca, s.BetaExternal)
	if e != nil {
		return nil, e
	}
	defer beta.close()
	p, e := startGateway(ctx, 2)
	if e != nil {
		return nil, e
	}
	defer p.kill()
	if e = p.ready(ctx, api); e != nil {
		return nil, e
	}
	if e = gatewayRoles(p); e != nil {
		return nil, e
	}
	if trace.serial.Load() != 2 {
		return nil, errors.New("cold current leaf not verified")
	}
	if e = old.call(ctx, "GET", "/healthz", "", nil, nil, 401); e != nil {
		return nil, e
	}
	current, e := tlsPolicyRead()
	if e != nil || current != s.Attempted {
		return nil, errors.New("production cold commit/replay did not establish exact revision2")
	}
	if m == tlsPolicyPost {
		if h, e := fileHash(tlsPolicyRoot + "/policy.json"); e != nil || h != s.Policy {
			return nil, errors.New("post-commit replay rewrote journal")
		}
	}
	if e = api.call(ctx, "POST", "/v1/sandboxes", s.RawKey, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	if e = beta.call(ctx, "POST", "/v1/sessions", s.SessionKey, nodeSpec(), nil, 410); e != nil {
		return nil, e
	}
	if e = beta.call(ctx, "POST", "/v1/sessions/"+s.Binding.ID+"/exec", "", map[string]any{"revision": 1, "argv": []string{"true"}}, nil, 410); e != nil {
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
	if e != nil || boot == s.Boots[0] || boot == s.Boots[1] {
		return nil, errors.New("fresh independent policy guest required")
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
	if e = operatorIdle(ctx, control, 0, 3); e != nil {
		return nil, e
	}
	if e = p.stop(ctx); e != nil {
		return nil, e
	}
	if e = waitNode(ctx, func() (bool, error) { return gatewayGone(p) == nil, nil }); e != nil {
		return nil, e
	}
	if e = n.stopOperatorDaemon(ctx); e != nil {
		return nil, e
	}
	for _, path := range []string{nodeBudgetInstances, nodeGroup + "/control", nodeGroup} {
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	}
	return map[string]any{"original_disk_actual_policy_config_identity_lock_and_destroyed_guests_before_daemon_checked": true, "ordinary_no_test_layer_cold_open_pending0_and_no_guest_revival": true, "current_revision2_verified_tls_leaf2_new_key200_old_key401": true, "old_raw_session_keys410_closed_route410_and_fresh_independent_kvm_full_gc": true, "no_policy_ledger_owner_control_authority_repair_by_fixture": true, "all_four_projects_zero_pools_idle_processes_reaped_node_subtree_removed": true, "pre_file_old_revision1_then_production_commit2": m == tlsPolicyPre, "post_commit_revision2_old_config1_refused_and_exact_replay": m == tlsPolicyPost, "policy_revision_before_start": int(s.Observed.Revision)}, nil
}
