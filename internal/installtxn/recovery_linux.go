//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// All production paths supply the fixed gateway implementation. An alternate
// filesystem/advance/manager exists only in package tests, never in CLI input.
type policyAdvance func(gateway.Config, []byte, []byte, string) error
type recoveryServiceManager interface {
	rotationServiceManager
	maintainIngress(context.Context, func() error) error
}
type recoveryWork struct {
	config                     gateway.Config
	base                       string
	payload, intent, candidate []byte
	record                     gateway.PolicyRecovery
	prior                      *gateway.PolicyRecovery
	priorSup                   *gateway.PolicySupersession
	visible, complete          bool
}

func validRecoveryArguments(expected uint64, request, supersedes string) bool {
	return expected >= 2 && expected != ^uint64(0) && requestPattern.MatchString(request) && requestPattern.MatchString(supersedes) && request != supersedes
}
func (f *filesystem) noPolicyRecovery() error {
	if e := f.noSupersession(); e != nil {
		return e
	}
	for _, name := range []string{"policy-recovery.json", ".policy-recovery.next"} {
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
func (f *filesystem) sourceCandidate(ctx context.Context, c gateway.Config, base string, p RotationPlan, expected uint64, request, supersedes string) ([]byte, error) {
	in, b, e := f.pinned(ctx, p.Policy, gateway.MaxSnapshotBytes, true)
	if e != nil {
		return nil, e
	}
	in.Close()
	if digest(b) != p.Policy.SHA256 {
		return nil, ErrInventory
	}
	var snapshot gateway.Snapshot
	if strictjson.Decode(b, &snapshot) != nil {
		return nil, ErrPolicy
	}
	raw, e := f.policyCandidate(c, base, snapshot, gateway.PolicySource{Path: p.Policy.Path, SHA256: p.Policy.SHA256}, expected, request)
	if e != nil {
		return nil, e
	}
	env, e := gateway.DecodeManagedEnvelope(c, raw, base)
	if e != nil {
		return nil, e
	}
	env.SupersededRequestID = supersedes
	return gateway.EncodePolicyEnvelope(env)
}

// Caller holds the original EX file lock, inside the EX operation scope. Every
// recognized record and scratch is proved before using a one-file override.
func (f *filesystem) prepareRecovery(ctx context.Context, t transaction, p RotationPlan, expected uint64, request, supersedes string, fallback []byte) (*recoveryWork, error) {
	if !validRecoveryArguments(expected, request, supersedes) {
		return nil, ErrPolicy
	}
	if request == t.RequestID || supersedes == t.RequestID {
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
	source := gateway.PolicySource{Path: p.Policy.Path, SHA256: p.Policy.SHA256}
	intent, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	recRaw, e := f.read(Root+"/policy-recovery.json", gateway.MaxPolicyRecovery, 0600)
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	hasRecord := e == nil
	supRaw, e := f.read(Root+"/policy-supersession.json", gateway.MaxPolicySupersession, 0600)
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	if yes, e := f.exists(Root + "/.policy-supersession.next"); e != nil {
		return nil, e
	} else if yes {
		return nil, ErrInventory
	}
	w := &recoveryWork{config: c, base: base, payload: payload, intent: intent}
	var previous gateway.PolicyIntent
	if len(supRaw) != 0 {
		if hasRecord {
			return nil, ErrConflict
		}
		sup, e := gateway.ValidateVisiblePolicySupersession(c, base, payload, intent, supRaw)
		if e != nil {
			return nil, e
		}
		if sup.RequestID != supersedes || sup.ExpectedRevision+1 != expected || current.Revision != expected || current.RequestID != supersedes {
			return nil, ErrConflict
		}
		w.priorSup = &sup
		previous = sup.NextIntent()
	} else if hasRecord {
		record, e := gateway.DecodePolicyRecovery(c, base, recRaw)
		if e != nil {
			return nil, e
		}
		if record.RequestID == request {
			if record.ExpectedRevision != expected || record.SupersedesRequestID != supersedes || record.Source != source {
				return nil, ErrConflict
			}
			if _, e = gateway.ValidateRecoveryPredecessor(c, base, payload, intent, recRaw); e != nil {
				if _, e = gateway.ValidateVisiblePolicyRecovery(c, base, payload, intent, recRaw, true); e != nil {
					return nil, e
				}
				w.visible = true
			}
			w.record = record
			previous = record.PreviousIntent
		} else {
			// A later explicit request may settle a *committed* failed predecessor
			// recovery without ACKing it. No recursive record or snapshot history.
			if record.RequestID != supersedes || record.ExpectedRevision+1 != expected || current.Revision != expected || current.RequestID != supersedes {
				return nil, ErrConflict
			}
			if _, e = gateway.ValidateVisiblePolicyRecovery(c, base, payload, intent, recRaw, true); e != nil {
				return nil, e
			}
			w.prior = &record
			previous = record.NextIntent()
		}
	} else if current.Revision == expected+1 && current.RequestID == request && current.SupersededRequestID == supersedes && current.Source == source {
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
		if current.Revision != expected || current.RequestID != supersedes {
			return nil, ErrConflict
		}
		previous, e = gateway.ValidateVisiblePolicyIntent(c, base, payload, intent)
		if e != nil {
			return nil, e
		}
	}
	if w.visible {
		w.candidate = payload
	} else if w.prior == nil && w.priorSup == nil && hasRecord {
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
	} // already pinned/validated in this operation before manager work
	if w.candidate == nil {
		w.candidate, e = f.sourceCandidate(ctx, c, base, p, expected, request, supersedes)
		if e != nil {
			return nil, e
		}
	}
	next, e := gateway.DecodeManagedEnvelope(c, w.candidate, base)
	if e != nil {
		return nil, e
	}
	if next.Revision != expected+1 || next.RequestID != request || next.SupersededRequestID != supersedes || next.Source != source {
		return nil, ErrConflict
	}
	if e = f.validateCandidate(c, base, w.candidate); e != nil {
		return nil, e
	}
	if !hasRecord || w.prior != nil || w.priorSup != nil {
		previousSHA, e := gateway.SnapshotDigest(current.Snapshot)
		if e != nil {
			return nil, e
		}
		w.record = gateway.PolicyRecovery{Version: 1, ExpectedRevision: expected, RequestID: request, SupersedesRequestID: supersedes, BaseCommitSHA256: base, ConfigSHA256: next.ConfigSHA256, InitialPolicySHA256: c.InitialPolicySHA256, OldPayloadSHA256: digest(payload), PreviousSnapshotSHA256: previousSHA, NewPayloadSHA256: digest(w.candidate), Source: source, PreviousIntent: previous}
	}
	if _, e = gateway.DecodePolicyRecovery(c, base, encode(w.record)); e != nil {
		return nil, e
	}
	if digest(w.candidate) != w.record.NewPayloadSHA256 {
		return nil, ErrConflict
	}
	for _, name := range []string{".intent.next", ".commit.next"} {
		if yes, e := f.exists(Root + "/" + name); e != nil {
			return nil, e
		} else if yes {
			return nil, ErrInventory
		}
	}
	recoveryScratch, e := f.exists(Root + "/.policy-recovery.next")
	if e != nil {
		return nil, e
	}
	if hasRecord && recoveryScratch {
		return nil, ErrInventory
	}
	if !hasRecord {
		if e = f.checkPrefix(Root+"/.policy-recovery.next", encode(w.record)); e != nil {
			return nil, e
		}
	}
	policyScratch, e := f.exists(Root + "/.policy.next")
	if e != nil {
		return nil, e
	}
	if w.visible || w.prior != nil || w.priorSup != nil || !hasRecord {
		if policyScratch {
			return nil, ErrInventory
		}
	} else if e = f.checkPrefix(Root+"/.policy.next", w.candidate); e != nil {
		return nil, e
	}
	intentScratch, e := f.exists(Root + "/.rotation-intent.next")
	if e != nil {
		return nil, e
	}
	var replacement gateway.PolicyIntent
	replaceAllowed := false
	if w.prior != nil {
		replacement = w.prior.NextIntent()
		replaceAllowed = bytes.Equal(intent, encode(w.prior.PreviousIntent))
	} else if w.visible {
		replacement = w.record.NextIntent()
		replaceAllowed = bytes.Equal(intent, encode(w.record.PreviousIntent))
	}
	if intentScratch {
		if !replaceAllowed {
			return nil, ErrInventory
		}
		if e = f.checkPrefix(Root+"/.rotation-intent.next", encode(replacement)); e != nil {
			return nil, e
		}
	}
	override := File{Path: gateway.ManagedPolicyPath, SHA256: digest(payload), Bytes: int64(len(payload)), Mode: 0600}
	if e = f.verifyTargetsAgainst(ctx, t, false, &override); e != nil {
		return nil, e
	}
	return w, nil
}

func (f *filesystem) replaceRecoveryIntent(ctx context.Context, old, next []byte) error {
	return f.replacePolicyIntent(ctx, old, next, "recovery-intent")
}
func (f *filesystem) replacePolicyIntent(ctx context.Context, old, next []byte, stage string) error {
	if e := f.exact(Root+"/rotation-intent.json", next, 0600); e == nil {
		if yes, e := f.exists(Root + "/.rotation-intent.next"); e != nil {
			return e
		} else if yes {
			return ErrInventory
		}
		return f.syncDir(Root)
	}
	if e := f.exact(Root+"/rotation-intent.json", old, 0600); e != nil {
		return e
	}
	if e := f.checkPrefix(Root+"/.rotation-intent.next", next); e != nil {
		return e
	}
	if e := f.putPrefix(Root+"/.rotation-intent.next", next, 0600, stage); e != nil {
		return e
	}
	in, e := f.open(Root+"/rotation-intent.json", unix.O_RDONLY, 0600)
	if e != nil {
		return e
	}
	defer in.Close()
	pinned, e := in.Stat()
	if e != nil {
		return e
	}
	sum, e := hashFile(ctx, in, int64(len(old)))
	if e != nil || sum != digest(old) {
		return ErrInventory
	}
	dir, e := f.directory(Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	var now unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), "rotation-intent.json", &now, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrInventory
	}
	var held unix.Stat_t
	if unix.Fstat(int(in.Fd()), &held) != nil || now.Dev != held.Dev || now.Ino != held.Ino || now.Nlink != 1 || pinned.Size() != int64(len(old)) {
		return ErrInventory
	}
	if e = unix.Renameat(int(dir.Fd()), ".rotation-intent.next", int(dir.Fd()), "rotation-intent.json"); e != nil {
		return e
	}
	if e = f.point(stage + "-renamed"); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point(stage + "-durable")
}
func (f *filesystem) removeRecovery(record gateway.PolicyRecovery) error {
	if e := f.exact(Root+"/policy-recovery.json", encode(record), 0600); e != nil {
		return e
	}
	dir, e := f.directory(Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = unix.Unlinkat(int(dir.Fd()), "policy-recovery.json", 0); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point("recovery-record-removed")
}
func (f *filesystem) advanceRecovery(t transaction, w *recoveryWork, advance policyAdvance) error {
	auth, e := f.read(Root+"/auth.json", 65536, 0600)
	if e != nil {
		return e
	}
	if digest(auth) != t.Plan.Auth.SHA256 || advance == nil {
		return ErrInventory
	}
	if e = advance(w.config, auth, w.payload, w.base); e != nil {
		return e
	}
	return f.point("recovery-predecessor-durable")
}
func (f *filesystem) publishRecovery(ctx context.Context, t transaction, w *recoveryWork, advance policyAdvance) error {
	if w.priorSup != nil {
		// This replacement DID commit: consume its exact current epoch, never reuse
		// it as an uncommitted proposal. Remove only its proven visible declaration.
		if e := f.advanceRecovery(t, w, advance); e != nil {
			return e
		}
		if e := f.removeSupersession(*w.priorSup); e != nil {
			return e
		}
		if e := f.record("policy-recovery", encode(w.record)); e != nil {
			return e
		}
		p := RotationPlan{Version: 1, Policy: firecracker.Asset{Path: w.record.Source.Path, SHA256: w.record.Source.SHA256}}
		var e error
		w, e = f.prepareRecovery(ctx, t, p, w.record.ExpectedRevision, w.record.RequestID, w.record.SupersedesRequestID, w.candidate)
		if e != nil {
			return e
		}
	}
	if w.prior != nil {
		// Current committed predecessor first, even when its prior recovery never
		// ACKed and its new-intent update was interrupted. No old request receipt.
		if e := f.advanceRecovery(t, w, advance); e != nil {
			return e
		}
		if e := f.replaceRecoveryIntent(ctx, encode(w.prior.PreviousIntent), encode(w.prior.NextIntent())); e != nil {
			return e
		}
		if e := f.removeRecovery(*w.prior); e != nil {
			return e
		}
		if e := f.record("policy-recovery", encode(w.record)); e != nil {
			return e
		}
		var e error
		p := RotationPlan{Version: 1, Policy: firecracker.Asset{Path: w.record.Source.Path, SHA256: w.record.Source.SHA256}}
		w, e = f.prepareRecovery(ctx, t, p, w.record.ExpectedRevision, w.record.RequestID, w.record.SupersedesRequestID, w.candidate)
		if e != nil {
			return e
		}
	}
	if !w.visible {
		if e := f.advanceRecovery(t, w, advance); e != nil {
			return e
		}
		if e := f.putPrefix(Root+"/.policy.next", w.candidate, 0600, "recovery-policy"); e != nil {
			return e
		}
		if e := f.point("recovery-policy-prepared"); e != nil {
			return e
		}
		if e := f.validateCandidate(w.config, w.base, w.candidate); e != nil {
			return e
		}
		if e := f.replacePolicy(ctx, w.payload, w.candidate); e != nil {
			return e
		}
	}
	if e := f.replaceRecoveryIntent(ctx, encode(w.record.PreviousIntent), encode(w.record.NextIntent())); e != nil {
		return e
	}
	if e := f.verifyTransaction(ctx, t); e != nil {
		return e
	}
	return f.point("recovery-files-confirmed")
}

// The EX operation scope spans journal, stop, durable predecessor advancement,
// publication, start/ACK and final receipt. File EX is never held across manager
// calls. The main-incarnation scope encloses even final intent removal.
func recoveryOperation(ctx context.Context, f *filesystem, p RotationPlan, expected uint64, request, supersedes string, manager serviceManager, advance policyAdvance) (Result, error) {
	var result Result
	if !validRecoveryArguments(expected, request, supersedes) {
		return result, ErrPolicy
	}
	m, ok := manager.(recoveryServiceManager)
	if !ok {
		return result, ErrPlatform
	}
	operationDone, e := f.operationLock(ctx, true)
	if e != nil {
		return result, e
	}
	defer operationDone()
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return result, e
	}
	t, e := f.readTransaction("commit")
	if e == nil {
		e = f.self(ctx, t.Plan)
	}
	var work *recoveryWork
	if e == nil {
		work, e = f.prepareRecovery(ctx, t, p, expected, request, supersedes, nil)
	}
	if e == nil && !work.complete && work.prior == nil && work.priorSup == nil {
		e = f.record("policy-recovery", encode(work.record))
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
		var fresh *recoveryWork
		if e == nil {
			fresh, e = f.prepareRecovery(ctx, t, p, expected, request, supersedes, work.candidate)
		}
		if e == nil {
			e = f.publishRecovery(ctx, t, fresh, advance)
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
		if e = f.removeRecovery(work.record); e != nil {
			return e
		} // remove declaration FIRST
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

func RecoverPolicy(ctx context.Context, path string, expected uint64, request, supersedes string) (Result, error) {
	if !validRecoveryArguments(expected, request, supersedes) {
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
	return recoveryOperation(ctx, f, p, expected, request, supersedes, systemManager{f, f.managerCommand}, gateway.AdvanceManagedPolicyState)
}

// Used by Reconcile only after observing a recovery under operation SH, then
// releasing SH before acquiring the EX scope. The EX path rechecks everything.
func (f *filesystem) declaredRecovery(t transaction, request string) (RotationPlan, uint64, string, error) {
	c, base, e := f.rotationBase(t)
	if e != nil {
		return RotationPlan{}, 0, "", e
	}
	b, e := f.read(Root+"/policy-recovery.json", gateway.MaxPolicyRecovery, 0600)
	if e != nil {
		return RotationPlan{}, 0, "", e
	}
	rec, e := gateway.DecodePolicyRecovery(c, base, b)
	if e != nil {
		return RotationPlan{}, 0, "", e
	}
	if rec.RequestID != request {
		return RotationPlan{}, 0, "", ErrConflict
	}
	return RotationPlan{Version: 1, Policy: firecracker.Asset{Path: rec.Source.Path, SHA256: rec.Source.SHA256}}, rec.ExpectedRevision, rec.SupersedesRequestID, nil
}
