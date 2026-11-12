//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// Positive policy maintenance for actual resultTransaction2 installations.
// The immutable Version2 commit/FULLConfig4 and initial gateway genesis stay
// unchanged; ONLY the existing typed one-file managed-policy protocol advances.
// NO legacy-transaction projection, old-version normalization, runtime image
// selection, retained-state migration/activation or rollback authority exists.
func (rb resultBootstrap) rotationBase(t resultTransaction) (gateway.Config, string, error) {
	f := rb.fs
	var c gateway.Config
	if t.Plan.Version != 2 || t.Plan.Policy == nil {
		return c, "", ErrPolicy
	}
	raw, e := f.read(Root+"/gateway.json", gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return c, "", e
	}
	if digest(raw) != t.Plan.Gateway.SHA256 || strictjson.Decode(raw, &c) != nil || c.InitialPolicySHA256 != t.Plan.Policy.SHA256 {
		return c, "", ErrInventory
	}
	base, e := gateway.ValidateManagedResultBase(c, raw, encode(t))
	return c, base, e
}

func (rb resultBootstrap) policyCandidate(c gateway.Config, base string, snapshot gateway.Snapshot, source gateway.PolicySource, expected uint64, request string) ([]byte, error) {
	binding, e := gateway.ManagedConfigDigest(c)
	if e != nil {
		return nil, e
	}
	p := gateway.PolicyEnvelope{Version: 1, Revision: expected + 1, ExpectedRevision: expected, RequestID: request, BaseCommitSHA256: base, ConfigSHA256: binding, InitialPolicySHA256: c.InitialPolicySHA256, Source: source, Snapshot: snapshot}
	b, e := gateway.EncodePolicyEnvelope(p)
	if e != nil {
		return nil, e
	}
	return b, rb.validateCandidate(c, base, b)
}

func (rb resultBootstrap) validateCandidate(c gateway.Config, base string, candidate []byte) error {
	f := rb.fs
	authRaw, e := f.read(Root+"/auth.json", 65536, 0600)
	if e != nil {
		return e
	}
	t, e := f.readResultTransaction("commit")
	if e != nil {
		return e
	}
	if digest(encode(t)) != base || digest(authRaw) != t.Plan.Auth.SHA256 {
		return ErrInventory
	}
	var auth access.Config
	if strictjson.Decode(authRaw, &auth) != nil {
		return ErrPolicy
	}
	authority, e := access.New(auth)
	if e != nil {
		return ErrPolicy
	}
	_, e = gateway.ValidateManagedSnapshot(c, candidate, base, authority, time.Now())
	return e
}

func (rb resultBootstrap) rotationLocked(ctx context.Context, t resultTransaction, p RotationPlan, expected uint64, request string, ready func() error) (gateway.PolicyEnvelope, error) {
	f := rb.fs
	var zero gateway.PolicyEnvelope
	if e := f.noPolicyRecovery(); e != nil {
		return zero, e
	}
	if expected == 0 || expected == ^uint64(0) || !requestPattern.MatchString(request) {
		return zero, ErrPolicy
	}
	if request == t.RequestID {
		return zero, ErrConflict
	}
	if _, e := DecodeRotation(encode(p)); e != nil {
		return zero, e
	}
	c, base, e := rb.rotationBase(t)
	if e != nil {
		return zero, e
	}
	old, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return zero, e
	}
	current, e := gateway.DecodeManagedEnvelope(c, old, base)
	if e != nil {
		return zero, e
	}
	source := gateway.PolicySource{Path: p.Policy.Path, SHA256: p.Policy.SHA256}
	intentRaw, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
	pending := e == nil
	var intent gateway.PolicyIntent
	if pending {
		intent, e = gateway.DecodePolicyIntent(c, base, intentRaw)
		if e != nil {
			return zero, e
		}
		if intent.RequestID != request || intent.ExpectedRevision != expected || intent.Source != source {
			return zero, ErrConflict
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return zero, e
	}
	if current.Revision == expected+1 && current.RequestID == request && current.Source == source {
		if e = rb.verifyTargets(ctx, t, true); e != nil {
			return zero, e
		}
		return current, nil // source-independent postcommit retry
	}
	if current.Revision > 1 && current.RequestID == request {
		return zero, ErrConflict
	}
	if current.Revision != expected {
		return zero, ErrConflict
	}
	if pending && digest(old) != intent.OldPayloadSHA256 {
		return zero, ErrInventory
	}
	for _, name := range []string{".intent.next", ".commit.next"} {
		if yes, e := f.exists(Root + "/" + name); e != nil || yes {
			if e != nil {
				return zero, e
			}
			return zero, ErrInventory
		}
	}
	var override *File
	if current.Revision > 1 {
		v := File{Path: gateway.ManagedPolicyPath, SHA256: digest(old), Bytes: int64(len(old)), Mode: 0600}
		override = &v
	}
	if e = rb.verifyPolicyTargetsAgainst(ctx, t, false, override); e != nil {
		return zero, e
	}
	intentScratch, e := f.exists(Root + "/.rotation-intent.next")
	if e != nil {
		return zero, e
	}
	policyScratch, e := f.exists(Root + "/.policy.next")
	if e != nil {
		return zero, e
	}
	if pending && intentScratch || !pending && policyScratch {
		return zero, ErrInventory
	}
	if !pending && !intentScratch {
		if ready == nil {
			return zero, ErrPolicy
		}
		if e = ready(); e != nil {
			return zero, e
		}
	}
	var candidate []byte
	if pending && policyScratch {
		b, e := f.readPrefix(Root+"/.policy.next", gateway.MaxSnapshotBytes)
		if e != nil {
			return zero, e
		}
		if digest(b) == intent.NewPayloadSHA256 {
			candidate = b
		}
	}
	if candidate == nil {
		in, sourceRaw, e := f.pinned(ctx, p.Policy, gateway.MaxSnapshotBytes, true)
		if e != nil {
			return zero, e
		}
		in.Close()
		if digest(sourceRaw) != p.Policy.SHA256 {
			return zero, ErrInventory
		}
		var snapshot gateway.Snapshot
		if strictjson.Decode(sourceRaw, &snapshot) != nil {
			return zero, ErrPolicy
		}
		candidate, e = rb.policyCandidate(c, base, snapshot, source, expected, request)
		if e != nil {
			return zero, e
		}
	}
	envelope, e := gateway.DecodeManagedEnvelope(c, candidate, base)
	if e != nil {
		return zero, e
	}
	if envelope.Revision != expected+1 || envelope.RequestID != request || envelope.Source != source {
		return zero, ErrConflict
	}
	if e = rb.validateCandidate(c, base, candidate); e != nil {
		return zero, e
	}
	proposed := gateway.PolicyIntent{Version: 1, ExpectedRevision: expected, RequestID: request, BaseCommitSHA256: base, ConfigSHA256: envelope.ConfigSHA256, InitialPolicySHA256: c.InitialPolicySHA256, OldPayloadSHA256: digest(old), NewPayloadSHA256: digest(candidate), Source: source}
	if pending && !bytes.Equal(encode(proposed), intentRaw) {
		return zero, ErrConflict
	}
	if e = f.checkPrefix(Root+"/.rotation-intent.next", encode(proposed)); e != nil {
		return zero, e
	}
	if e = f.checkPrefix(Root+"/.policy.next", candidate); e != nil {
		return zero, e
	}
	if e = f.record("rotation-intent", encode(proposed)); e != nil {
		return zero, e
	}
	if e = f.putPrefix(Root+"/.policy.next", candidate, 0600, "policy"); e != nil {
		return zero, e
	}
	if e = f.point("policy-prepared"); e != nil {
		return zero, e
	}
	if e = f.replacePolicy(ctx, old, candidate); e != nil {
		return zero, e
	}
	if e = rb.verifyTargets(ctx, t, true); e != nil {
		return zero, e
	}
	if e = f.point("policy-confirmed"); e != nil {
		return zero, e
	}
	return envelope, nil
}

func (rb resultBootstrap) reconfigurePolicyOperation(ctx context.Context, p RotationPlan, expected uint64, request string, manager serviceManager) (Result, error) {
	f := rb.fs
	if !resultBounded(ctx) || rb.programs == nil || expected == 0 || expected == ^uint64(0) || !requestPattern.MatchString(request) {
		return Result{}, ErrPolicy
	}
	var zero Result
	operationDone, e := f.ordinaryOperationLock(ctx, false)
	if e != nil {
		return zero, e
	}
	defer operationDone()
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return zero, e
	}
	t, e := f.readResultTransaction("commit")
	if e == nil {
		e = f.self(ctx, t.Plan)
	}
	if e == nil {
		_, e = rb.rotationLocked(ctx, t, p, expected, request, func() error {
			yes, e := rb.policyReceipt(ctx, t, manager, false)
			if e != nil {
				return e
			}
			if !yes {
				return ErrPlatform
			}
			return nil
		})
	}
	unlock()
	if e != nil {
		return zero, e
	}
	return rb.reconcilePolicy(ctx, request, manager)
}

func (rb resultBootstrap) declaredRotation(t resultTransaction, request string) (RotationPlan, uint64, error) {
	f := rb.fs
	var p RotationPlan
	c, base, e := rb.rotationBase(t)
	if e != nil {
		return p, 0, e
	}
	raw, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
	if e == nil {
		i, e := gateway.DecodePolicyIntent(c, base, raw)
		if e != nil {
			return p, 0, e
		}
		if i.RequestID != request {
			return p, 0, ErrConflict
		}
		return RotationPlan{Version: 1, Policy: firecracker.Asset{Path: i.Source.Path, SHA256: i.Source.SHA256}}, i.ExpectedRevision, nil
	} else if !errors.Is(e, unix.ENOENT) {
		return p, 0, e
	}
	raw, e = f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return p, 0, e
	}
	envelope, e := gateway.DecodeManagedEnvelope(c, raw, base)
	if e != nil {
		return p, 0, e
	}
	if envelope.Revision < 2 || envelope.RequestID != request {
		return p, 0, ErrConflict
	}
	return RotationPlan{Version: 1, Policy: firecracker.Asset{Path: envelope.Source.Path, SHA256: envelope.Source.SHA256}}, envelope.ExpectedRevision, nil
}

func (rb resultBootstrap) reconcilePolicy(ctx context.Context, request string, manager serviceManager) (Result, error) {
	f := rb.fs
	var zero Result
	if !requestPattern.MatchString(request) {
		return zero, ErrPolicy
	}
	managed, ok := manager.(rotationServiceManager)
	if !ok {
		return zero, ErrPlatform
	}
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return zero, e
	}
	t, e := f.readResultTransaction("commit")
	if e == nil {
		e = f.self(ctx, t.Plan)
	}
	var p RotationPlan
	var expected uint64
	var envelope gateway.PolicyEnvelope
	if e == nil {
		p, expected, e = rb.declaredRotation(t, request)
	}
	if e == nil {
		envelope, e = rb.rotationLocked(ctx, t, p, expected, request, nil)
	}
	unlock()
	if e != nil {
		return zero, e
	}
	sha, e := gateway.SnapshotDigest(envelope.Snapshot)
	if e != nil {
		return zero, e
	}
	art, e := descriptor(t.Release)
	if e != nil {
		return zero, e
	}
	yes, e := managed.activateManaged(ctx, envelope.Revision, sha, art["gateway"].SHA256)
	if e != nil {
		return zero, e
	}
	if !yes {
		return zero, ErrPlatform
	}
	unlock, e = f.existingLock(ctx, true)
	if e != nil {
		return zero, e
	}
	defer unlock()
	current, e := f.readResultTransaction("commit")
	if e != nil {
		return zero, e
	}
	if !bytes.Equal(encode(current), encode(t)) {
		return zero, ErrConflict
	}
	if e = rb.verifyTargets(ctx, t, true); e != nil {
		return zero, e
	}
	_, now, e := rb.effectivePolicy(t, true)
	if e != nil {
		return zero, e
	}
	if now.Revision != envelope.Revision || now.RequestID != request || now.Source != envelope.Source {
		return zero, ErrConflict
	}
	yes, e = rb.policyReceipt(ctx, t, manager, false)
	if e != nil {
		return zero, e
	}
	if !yes {
		return zero, ErrPlatform
	}
	if e = rb.removePolicyIntent(t, request); e != nil {
		return zero, e
	}
	r, e := rb.committedResult(t)
	if e != nil {
		return zero, e
	}
	r.ManagerReconciled = true
	return r, nil
}

func (rb resultBootstrap) removePolicyIntent(t resultTransaction, request string) error {
	f := rb.fs
	c, base, e := rb.rotationBase(t)
	if e != nil {
		return e
	}
	raw, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	payload, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return e
	}
	intent, e := gateway.ValidateVisiblePolicyIntent(c, base, payload, raw)
	if e != nil {
		return e
	}
	if intent.RequestID != request {
		return ErrConflict
	}
	dir, e := f.directory(Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = unix.Unlinkat(int(dir.Fd()), "rotation-intent.json", 0); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point("policy-intent-removed")
}

// Only this guarded new-version caller invokes the existing verifier tail.
// Every original fresh inventory/hash/generatedfile/8program-FD check remains.
func (rb resultBootstrap) verifyPolicyTargetsAgainst(ctx context.Context, t resultTransaction, committed bool, override *File) error {
	if rb.programs == nil || !validResultTransaction(t) {
		return ErrInventory
	}
	return rb.verifyTargetsAfterPolicy(ctx, t, committed, override)
}

func (rb resultBootstrap) reconcilePolicyOperation(ctx context.Context, request string, manager serviceManager) (Result, error) {
	if !resultBounded(ctx) || !requestPattern.MatchString(request) || rb.programs == nil {
		return Result{}, ErrPolicy
	}
	done, e := rb.fs.ordinaryOperationLock(ctx, false)
	if e != nil {
		return Result{}, e
	}
	defer done() // SAME original OFD lease spans activation and final fresh ACK.
	return rb.reconcilePolicy(ctx, request, manager)
}

func ReconfigureResults(ctx context.Context, path string, expected uint64, request string) (Result, error) {
	if !resultBounded(ctx) || expected == 0 || expected == ^uint64(0) || !requestPattern.MatchString(request) {
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
	plan, e := DecodeRotation(raw)
	if e != nil {
		return Result{}, e
	}
	return newResultBootstrap(f).reconfigurePolicyOperation(ctx, plan, expected, request, systemManager{f, f.managerCommand})
}

func ReconcileResultsPolicy(ctx context.Context, request string) (Result, error) {
	if !resultBounded(ctx) || !requestPattern.MatchString(request) {
		return Result{}, ErrPolicy
	}
	f, e := systemFS()
	if e != nil {
		return Result{}, e
	}
	defer f.root.Close()
	return newResultBootstrap(f).reconcilePolicyOperation(ctx, request, systemManager{f, f.managerCommand})
}
