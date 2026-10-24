//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"golang.org/x/sys/unix"
)

type supersessionWork struct {
	config                     gateway.Config
	base                       string
	payload, intent, candidate []byte
	record                     gateway.PolicySupersession
	prior                      *gateway.PolicySupersession
	visible, complete          bool
}

func validSupersessionArguments(expected uint64, request, replaces string) bool {
	return expected > 0 && expected != ^uint64(0) && requestPattern.MatchString(request) && requestPattern.MatchString(replaces) && request != replaces
}
func (f *filesystem) noSupersession() error {
	for _, name := range []string{"policy-supersession.json", ".policy-supersession.next"} {
		yes, e := f.exists(Root + "/" + name)
		if e != nil {
			return e
		}
		if yes {
			return ErrConflict
		}
	}
	return nil
}

// Recovery authority may disappear ONLY after the future intent is durable.
// No old candidate snapshot/key is needed to validate this metadata transition.
func validateSupersededRecovery(c gateway.Config, base string, payload, intent, raw []byte, s gateway.PolicySupersession) error {
	if s.RecoverySHA256 == "" {
		if len(raw) != 0 {
			return ErrInventory
		}
		return nil
	}
	if len(raw) == 0 {
		if !bytes.Equal(intent, encode(s.NextIntent())) {
			return ErrInventory
		}
		return nil
	}
	if digest(raw) != s.RecoverySHA256 {
		return ErrInventory
	}
	r, e := gateway.ValidateRecoveryPredecessor(c, base, payload, encode(s.PreviousIntent), raw)
	if e != nil {
		return e
	}
	if r.ExpectedRevision != s.ExpectedRevision || r.RequestID != s.ReplacesRequestID {
		return ErrConflict
	}
	return nil
}
func (f *filesystem) prepareSupersession(ctx context.Context, t transaction, p RotationPlan, expected uint64, request, replaces string, fallback []byte) (*supersessionWork, error) {
	if !validSupersessionArguments(expected, request, replaces) {
		return nil, ErrPolicy
	}
	if request == t.RequestID || replaces == t.RequestID {
		return nil, ErrConflict
	}
	if _, e := DecodeRotation(encode(p)); e != nil {
		return nil, e
	}
	c, base, e := f.rotationBase(t)
	if e != nil {
		return nil, e
	}
	payload, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return nil, e
	}
	current, e := gateway.DecodeManagedEnvelope(c, payload, base)
	if e != nil {
		return nil, e
	}
	intent, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	raw, e := f.read(Root+"/policy-supersession.json", gateway.MaxPolicySupersession, 0600)
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	hasRecord := e == nil
	recovery, e := f.read(Root+"/policy-recovery.json", gateway.MaxPolicyRecovery, 0600)
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	source := gateway.PolicySource{Path: p.Policy.Path, SHA256: p.Policy.SHA256}
	w := &supersessionWork{config: c, base: base, payload: payload, intent: intent}
	var previous gateway.PolicyIntent
	var recoverySHA string
	var anchor *gateway.PolicySupersession
	if hasRecord {
		s, e := gateway.DecodePolicySupersession(c, base, raw)
		if e != nil {
			return nil, e
		}
		if s.RequestID == request {
			if s.ExpectedRevision != expected || s.ReplacesRequestID != replaces || s.Source != source {
				return nil, ErrConflict
			}
			if _, e = gateway.ValidateSupersessionPredecessor(c, base, payload, intent, raw); e != nil {
				if _, e = gateway.ValidateVisiblePolicySupersession(c, base, payload, intent, raw); e != nil {
					return nil, e
				}
				w.visible = true
			}
			w.record = s
			anchor = &w.record
		} else {
			if s.RequestID != replaces || s.ExpectedRevision != expected {
				return nil, ErrConflict
			}
			if _, e = gateway.ValidateSupersessionPredecessor(c, base, payload, intent, raw); e != nil {
				return nil, e
			}
			w.prior = &s
			anchor = &s
			previous = s.NextIntent()
		}
		if w.visible {
			if len(recovery) != 0 {
				return nil, ErrInventory
			}
		} else if e = validateSupersededRecovery(c, base, payload, intent, recovery, *anchor); e != nil {
			return nil, e
		}
	} else if current.Revision == expected+1 && current.RequestID == request && current.ReplacedPendingRequestID == replaces && current.Source == source {
		if len(recovery) != 0 {
			return nil, ErrInventory
		}
		if e = f.noPolicyRecovery(); e != nil {
			return nil, e
		}
		if e = f.verifyTransaction(ctx, t); e != nil {
			return nil, e
		}
		if e = f.validateCandidate(c, base, payload); e != nil {
			return nil, e
		}
		w.visible = true
		w.complete = true
		w.candidate = payload
		return w, nil
	} else {
		if current.Revision != expected || current.RequestID == request {
			return nil, ErrConflict
		}
		if len(recovery) != 0 {
			r, e := gateway.ValidateRecoveryPredecessor(c, base, payload, intent, recovery)
			if e != nil {
				return nil, e
			}
			if r.ExpectedRevision != expected || r.RequestID != replaces {
				return nil, ErrConflict
			}
			previous = r.PreviousIntent
			recoverySHA = digest(recovery)
		} else {
			previous, e = gateway.DecodePolicyIntent(c, base, intent)
			if e != nil {
				return nil, e
			}
			if previous.ExpectedRevision != expected || previous.RequestID != replaces || previous.OldPayloadSHA256 != digest(payload) {
				return nil, ErrConflict
			}
		}
	}
	if w.visible {
		w.candidate = payload
	} else if hasRecord && w.prior == nil {
		if digest(fallback) == w.record.NewPayloadSHA256 {
			w.candidate = fallback
		} else {
			b, e := f.readPrefix(Root+"/.policy.next", gateway.MaxSnapshotBytes)
			if e != nil && !errors.Is(e, unix.ENOENT) {
				return nil, e
			}
			if digest(b) == w.record.NewPayloadSHA256 {
				w.candidate = b
			}
		}
	}
	if w.candidate == nil && len(fallback) != 0 {
		w.candidate = fallback
	}
	if w.candidate == nil {
		b, e := f.sourceCandidate(ctx, c, base, p, expected, request, "")
		if e != nil {
			return nil, e
		}
		env, e := gateway.DecodeManagedEnvelope(c, b, base)
		if e != nil {
			return nil, e
		}
		env.ReplacedPendingRequestID = replaces
		w.candidate, e = gateway.EncodePolicyEnvelope(env)
		if e != nil {
			return nil, e
		}
	}
	next, e := gateway.DecodeManagedEnvelope(c, w.candidate, base)
	if e != nil {
		return nil, e
	}
	if next.Revision != expected+1 || next.RequestID != request || next.ReplacedPendingRequestID != replaces || next.SupersededRequestID != "" || next.Source != source {
		return nil, ErrConflict
	}
	if e = f.validateCandidate(c, base, w.candidate); e != nil {
		return nil, e
	}
	if !hasRecord || w.prior != nil {
		sha, e := gateway.SnapshotDigest(current.Snapshot)
		if e != nil {
			return nil, e
		}
		w.record = gateway.PolicySupersession{Version: 1, ExpectedRevision: expected, RequestID: request, ReplacesRequestID: replaces, BaseCommitSHA256: base, ConfigSHA256: next.ConfigSHA256, InitialPolicySHA256: c.InitialPolicySHA256, OldPayloadSHA256: digest(payload), PreviousSnapshotSHA256: sha, NewPayloadSHA256: digest(w.candidate), Source: source, PreviousIntent: previous, RecoverySHA256: recoverySHA}
	}
	if _, e = gateway.DecodePolicySupersession(c, base, encode(w.record)); e != nil {
		return nil, e
	}
	if digest(w.candidate) != w.record.NewPayloadSHA256 {
		return nil, ErrConflict
	}
	for _, name := range []string{".intent.next", ".commit.next", ".policy-recovery.next"} {
		yes, e := f.exists(Root + "/" + name)
		if e != nil {
			return nil, e
		}
		if yes {
			return nil, ErrInventory
		}
	}
	yes, e := f.exists(Root + "/.policy-supersession.next")
	if e != nil {
		return nil, e
	}
	if hasRecord && yes {
		return nil, ErrInventory
	}
	if !hasRecord {
		if e = f.checkPrefix(Root+"/.policy-supersession.next", encode(w.record)); e != nil {
			return nil, e
		}
	}
	yes, e = f.exists(Root + "/.rotation-intent.next")
	if e != nil {
		return nil, e
	}
	if yes {
		if anchor == nil || !bytes.Equal(intent, encode(anchor.PreviousIntent)) {
			return nil, ErrInventory
		}
		if e = f.checkPrefix(Root+"/.rotation-intent.next", encode(anchor.NextIntent())); e != nil {
			return nil, e
		}
	}
	// This explicit operation can discard bounded private proposal DATA, never
	// an authority record. Even partial opaque bytes need no abandoned key. Their
	// inode/content is re-pinned before unlink; actual installed/runtime N is
	// proven first under stopped ingress. Ordinary operations never gain this.
	_, e = f.readPrefix(Root+"/.policy.next", gateway.MaxSnapshotBytes)
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	if w.visible && e == nil {
		return nil, ErrInventory
	}
	override := File{Path: gateway.ManagedPolicyPath, SHA256: digest(payload), Bytes: int64(len(payload)), Mode: 0600}
	if e = f.verifyTargetsAgainst(ctx, t, false, &override); e != nil {
		return nil, e
	}
	return w, nil
}

// Only this fixed proposal-data pathname is discardable, only in the explicit
// maintenance operation after durable-state proof. No arbitrary cleanup path.
func (f *filesystem) discardProposal(ctx context.Context, candidate []byte) error {
	in, e := f.open(Root+"/.policy.next", unix.O_RDONLY, 0600)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	defer in.Close()
	b, e := io.ReadAll(io.LimitReader(in, gateway.MaxSnapshotBytes+1))
	if e != nil {
		return e
	}
	if len(b) > gateway.MaxSnapshotBytes {
		return ErrInventory
	}
	if candidate != nil && bytes.HasPrefix(candidate, b) {
		return nil
	} // retain complete/current prefixes for source-independent retry
	info, e := in.Stat()
	if e != nil {
		return e
	}
	sum, e := hashFile(ctx, in, int64(len(b)))
	if e != nil || info.Size() != int64(len(b)) || sum != digest(b) {
		return ErrInventory
	}
	if e = f.point("supersession-discard-ready"); e != nil {
		return e
	}
	dir, e := f.directory(Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	var held, now unix.Stat_t
	if unix.Fstat(int(in.Fd()), &held) != nil || unix.Fstatat(int(dir.Fd()), ".policy.next", &now, unix.AT_SYMLINK_NOFOLLOW) != nil || now.Dev != held.Dev || now.Ino != held.Ino || now.Nlink != 1 || now.Mode&07777 != 0600 || now.Size != info.Size() {
		return ErrInventory
	}
	if e = unix.Unlinkat(int(dir.Fd()), ".policy.next", 0); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point("supersession-proposal-discarded")
}
func (f *filesystem) removeSupersession(s gateway.PolicySupersession) error {
	if e := f.exact(Root+"/policy-supersession.json", encode(s), 0600); e != nil {
		return e
	}
	dir, e := f.directory(Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = unix.Unlinkat(int(dir.Fd()), "policy-supersession.json", 0); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point("supersession-record-removed")
}
func (f *filesystem) proveSupersessionState(t transaction, w *supersessionWork, s gateway.PolicySupersession, advance, confirm policyAdvance) error {
	auth, e := f.read(Root+"/auth.json", 65536, 0600)
	if e != nil {
		return e
	}
	if digest(auth) != t.Plan.Auth.SHA256 || advance == nil || confirm == nil {
		return ErrInventory
	}
	if s.RecoverySHA256 != "" {
		if e = advance(w.config, auth, w.payload, w.base); e != nil {
			return e
		}
		if e = f.point("supersession-predecessor-durable"); e != nil {
			return e
		}
	}
	if e = confirm(w.config, auth, w.payload, w.base); e != nil {
		return e
	}
	return f.point("supersession-current-confirmed")
}
func (f *filesystem) settleSupersession(ctx context.Context, t transaction, w *supersessionWork, s gateway.PolicySupersession, advance, confirm policyAdvance, candidate []byte) error {
	if e := f.proveSupersessionState(t, w, s, advance, confirm); e != nil {
		return e
	}
	if e := f.discardProposal(ctx, candidate); e != nil {
		return e
	}
	if e := f.replacePolicyIntent(ctx, encode(s.PreviousIntent), encode(s.NextIntent()), "supersession-intent"); e != nil {
		return e
	}
	if s.RecoverySHA256 != "" {
		raw, e := f.read(Root+"/policy-recovery.json", gateway.MaxPolicyRecovery, 0600)
		if e == nil {
			if digest(raw) != s.RecoverySHA256 {
				return ErrInventory
			}
			r, e := gateway.DecodePolicyRecovery(w.config, w.base, raw)
			if e != nil {
				return e
			}
			if e = f.removeRecovery(r); e != nil {
				return e
			}
		} else if !errors.Is(e, unix.ENOENT) {
			return e
		}
	}
	return nil
}
func (f *filesystem) publishSupersession(ctx context.Context, t transaction, w *supersessionWork, advance, confirm policyAdvance) error {
	if w.prior != nil {
		if e := f.settleSupersession(ctx, t, w, *w.prior, advance, confirm, nil); e != nil {
			return e
		}
		if e := f.removeSupersession(*w.prior); e != nil {
			return e
		}
		if e := f.record("policy-supersession", encode(w.record)); e != nil {
			return e
		}
		p := RotationPlan{Version: 1, Policy: firecracker.Asset{Path: w.record.Source.Path, SHA256: w.record.Source.SHA256}}
		var e error
		w, e = f.prepareSupersession(ctx, t, p, w.record.ExpectedRevision, w.record.RequestID, w.record.ReplacesRequestID, w.candidate)
		if e != nil {
			return e
		}
	}
	if !w.visible {
		if e := f.settleSupersession(ctx, t, w, w.record, advance, confirm, w.candidate); e != nil {
			return e
		}
		if e := f.putPrefix(Root+"/.policy.next", w.candidate, 0600, "supersession-policy"); e != nil {
			return e
		}
		if e := f.point("supersession-policy-prepared"); e != nil {
			return e
		}
		if e := f.validateCandidate(w.config, w.base, w.candidate); e != nil {
			return e
		}
		if e := f.replacePolicy(ctx, w.payload, w.candidate); e != nil {
			return e
		}
	}
	if e := f.verifyTransaction(ctx, t); e != nil {
		return e
	}
	return f.point("supersession-files-confirmed")
}
func supersessionOperation(ctx context.Context, f *filesystem, p RotationPlan, expected uint64, request, replaces string, manager serviceManager, advance, confirm policyAdvance) (Result, error) {
	var result Result
	if !validSupersessionArguments(expected, request, replaces) {
		return result, ErrPolicy
	}
	m, ok := manager.(recoveryServiceManager)
	if !ok {
		return result, ErrPlatform
	}
	done, e := f.operationLock(ctx, true)
	if e != nil {
		return result, e
	}
	defer done()
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return result, e
	}
	t, e := f.readTransaction("commit")
	if e == nil {
		e = f.self(ctx, t.Plan)
	}
	var work *supersessionWork
	if e == nil {
		work, e = f.prepareSupersession(ctx, t, p, expected, request, replaces, nil)
	}
	if e == nil && !work.complete && work.prior == nil {
		e = f.record("policy-supersession", encode(work.record))
	}
	unlock()
	if e != nil {
		return result, e
	}
	if work.complete {
		return reconcileRotation(ctx, f, request, manager)
	}
	e = m.maintainIngress(ctx, func() error {
		unlock, e := f.existingLock(ctx, true)
		if e != nil {
			return e
		}
		current, e := f.readTransaction("commit")
		if e == nil && !bytes.Equal(encode(current), encode(t)) {
			e = ErrConflict
		}
		if e == nil {
			e = f.self(ctx, t.Plan)
		}
		var fresh *supersessionWork
		if e == nil {
			fresh, e = f.prepareSupersession(ctx, t, p, expected, request, replaces, work.candidate)
		}
		if e == nil {
			e = f.publishSupersession(ctx, t, fresh, advance, confirm)
		}
		unlock()
		if e != nil {
			return e
		}
		env, e := gateway.DecodeManagedEnvelope(work.config, work.candidate, work.base)
		if e != nil {
			return e
		}
		sha, e := gateway.SnapshotDigest(env.Snapshot)
		if e != nil {
			return e
		}
		art, e := descriptor(t.Release)
		if e != nil {
			return e
		}
		yes, e := m.activateManaged(ctx, env.Revision, sha, art["gateway"].SHA256)
		if e != nil {
			return e
		}
		if !yes {
			return ErrPlatform
		}
		unlock, e = f.existingLock(ctx, true)
		if e != nil {
			return e
		}
		defer unlock()
		current, e = f.readTransaction("commit")
		if e != nil {
			return e
		}
		if !bytes.Equal(encode(current), encode(t)) {
			return ErrConflict
		}
		if e = f.verifyTransaction(ctx, t); e != nil {
			return e
		}
		payload, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
		if e != nil {
			return e
		}
		if !bytes.Equal(payload, work.candidate) {
			return ErrConflict
		}
		if e = f.validateCandidate(work.config, work.base, payload); e != nil {
			return e
		}
		yes, e = f.policyReceipt(ctx, t, manager, false)
		if e != nil {
			return e
		}
		if !yes {
			return ErrPlatform
		}
		if e = f.removeSupersession(work.record); e != nil {
			return e
		} // declaration FIRST, then matching intent
		if e = f.removePolicyIntent(t, request); e != nil {
			return e
		}
		result, e = f.committedResult(t)
		if e != nil {
			return e
		}
		result.ManagerReconciled = true
		return nil
	})
	if e != nil {
		return Result{}, e
	}
	return result, nil
}
func ReplacePendingPolicy(ctx context.Context, path string, expected uint64, request, replaces string) (Result, error) {
	if !validSupersessionArguments(expected, request, replaces) {
		return Result{}, ErrPolicy
	}
	f, e := systemFS()
	if e != nil {
		return Result{}, e
	}
	defer f.root.Close()
	raw, e := f.read(path, MaxPlan, 0600)
	if e != nil {
		return Result{}, e
	}
	p, e := DecodeRotation(raw)
	if e != nil {
		return Result{}, e
	}
	return supersessionOperation(ctx, f, p, expected, request, replaces, systemManager{f, f.managerCommand}, gateway.AdvanceManagedPolicyState, gateway.ConfirmManagedPolicyState)
}
func (f *filesystem) declaredSupersession(t transaction, request string) (RotationPlan, uint64, string, error) {
	c, base, e := f.rotationBase(t)
	if e != nil {
		return RotationPlan{}, 0, "", e
	}
	b, e := f.read(Root+"/policy-supersession.json", gateway.MaxPolicySupersession, 0600)
	if e != nil {
		return RotationPlan{}, 0, "", e
	}
	s, e := gateway.DecodePolicySupersession(c, base, b)
	if e != nil {
		return RotationPlan{}, 0, "", e
	}
	if s.RequestID != request {
		return RotationPlan{}, 0, "", ErrConflict
	}
	return RotationPlan{Version: 1, Policy: firecracker.Asset{Path: s.Source.Path, SHA256: s.Source.SHA256}}, s.ExpectedRevision, s.ReplacesRequestID, nil
}
