//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

func (f *filesystem) rotationBase(t transaction) (gateway.Config, string, error) {
	var c gateway.Config
	if t.Plan.Version != 2 || t.Plan.Policy == nil {
		return c, "", ErrPolicy
	}
	b, e := f.read(Root+"/gateway.json", gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return c, "", e
	}
	if digest(b) != t.Plan.Gateway.SHA256 || strictjson.Decode(b, &c) != nil || c.InitialPolicySHA256 != t.Plan.Policy.SHA256 {
		return c, "", ErrInventory
	}
	base, e := gateway.ValidateManagedBase(c, b, encode(t))
	return c, base, e
}
func (f *filesystem) policyCandidate(c gateway.Config, base string, snapshot gateway.Snapshot, source gateway.PolicySource, expected uint64, request string) ([]byte, error) {
	binding, e := gateway.ManagedConfigDigest(c)
	if e != nil {
		return nil, e
	}
	p := gateway.PolicyEnvelope{Version: 1, Revision: expected + 1, ExpectedRevision: expected, RequestID: request, BaseCommitSHA256: base, ConfigSHA256: binding, InitialPolicySHA256: c.InitialPolicySHA256, Source: source, Snapshot: snapshot}
	b, e := gateway.EncodePolicyEnvelope(p)
	if e != nil {
		return nil, e
	}
	return b, f.validateCandidate(c, base, b)
}
func (f *filesystem) validateCandidate(c gateway.Config, base string, raw []byte) error {
	b, e := f.read(Root+"/auth.json", 65536, 0600)
	if e != nil {
		return e
	}
	t, e := f.readTransaction("commit")
	if e != nil {
		return e
	}
	if digest(encode(t)) != base || digest(b) != t.Plan.Auth.SHA256 {
		return ErrInventory
	}
	var auth access.Config
	if strictjson.Decode(b, &auth) != nil {
		return ErrPolicy
	}
	authority, e := access.New(auth)
	if e != nil {
		return ErrPolicy
	}
	_, e = gateway.ValidateManagedSnapshot(c, raw, base, authority, time.Now())
	return e
}
func (f *filesystem) readPrefix(path string, max int64) ([]byte, error) {
	in, e := f.open(path, unix.O_RDONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer in.Close()
	b, e := io.ReadAll(io.LimitReader(in, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, ErrInventory
	}
	return b, nil
}
func (f *filesystem) checkPrefix(path string, expected []byte) error {
	b, e := f.readPrefix(path, int64(len(expected)))
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	if !bytes.HasPrefix(expected, b) {
		return ErrInventory
	}
	return nil
}
func (f *filesystem) replacePolicy(ctx context.Context, old []byte, candidate []byte) error {
	in, e := f.open(gateway.ManagedPolicyPath, unix.O_RDONLY, 0600)
	if e != nil {
		return e
	}
	defer in.Close()
	info, e := in.Stat()
	if e != nil {
		return e
	}
	sum, e := hashFile(ctx, in, int64(len(old)))
	if e != nil || sum != digest(old) {
		return ErrInventory
	}
	if e = f.exact(Root+"/.policy.next", candidate, 0600); e != nil {
		return e
	}
	dir, e := f.directory(Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	var current unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), "gateway-policy.json", &current, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrInventory
	}
	var pinned unix.Stat_t
	if unix.Fstat(int(in.Fd()), &pinned) != nil || current.Dev != pinned.Dev || current.Ino != pinned.Ino || current.Nlink != 1 || info.Size() != int64(len(old)) {
		return ErrInventory
	}
	if e = unix.Renameat(int(dir.Fd()), ".policy.next", int(dir.Fd()), "gateway-policy.json"); e != nil {
		return e
	}
	if e = f.point("policy-renamed"); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point("policy-durable")
}

// Caller owns the original exclusive install lock. Only the typed one-file
// policy authority changes. Keep its intent until real activation and final
// full install verification, not merely file rename, signal or RPC submission.
func (f *filesystem) rotationLocked(ctx context.Context, t transaction, p RotationPlan, expected uint64, request string, ready func() error) (gateway.PolicyEnvelope, error) {
	var zero gateway.PolicyEnvelope
	if expected == 0 || expected == ^uint64(0) || !requestPattern.MatchString(request) {
		return zero, ErrPolicy
	}
	if request == t.RequestID {
		return zero, ErrConflict
	}
	if _, e := DecodeRotation(encode(p)); e != nil {
		return zero, e
	}
	c, base, e := f.rotationBase(t)
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
		if e = f.verifyTransaction(ctx, t); e != nil {
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
	if e = f.verifyTargetsAgainst(ctx, t, false, override); e != nil {
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
		in, b, e := f.pinned(ctx, p.Policy, gateway.MaxSnapshotBytes, true)
		if e != nil {
			return zero, e
		}
		in.Close()
		if digest(b) != p.Policy.SHA256 {
			return zero, ErrInventory
		}
		var snapshot gateway.Snapshot
		if strictjson.Decode(b, &snapshot) != nil {
			return zero, ErrPolicy
		}
		candidate, e = f.policyCandidate(c, base, snapshot, source, expected, request)
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
	if e = f.validateCandidate(c, base, candidate); e != nil {
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
	if e = f.verifyTransaction(ctx, t); e != nil {
		return zero, e
	}
	if e = f.point("policy-confirmed"); e != nil {
		return zero, e
	}
	return envelope, nil
}

func Reconfigure(ctx context.Context, path string, expected uint64, request string) (Result, error) {
	var zero Result
	if expected == 0 || expected == ^uint64(0) || !requestPattern.MatchString(request) {
		return zero, ErrPolicy
	}
	f, e := systemFS()
	if e != nil {
		return zero, e
	}
	defer f.root.Close()
	raw, e := f.read(path, MaxPlan, 0600)
	if e != nil {
		return zero, e
	}
	p, e := DecodeRotation(raw)
	if e != nil {
		return zero, e
	}
	return reconfigureOperation(ctx, f, p, expected, request, systemManager{f, f.managerCommand})
}

func reconfigureOperation(ctx context.Context, f *filesystem, p RotationPlan, expected uint64, request string, manager serviceManager) (Result, error) {
	var zero Result
	operationDone, e := f.operationLock(ctx, false)
	if e != nil {
		return zero, e
	}
	defer operationDone()
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return zero, e
	}
	t, e := f.readTransaction("commit")
	if e == nil {
		e = f.self(ctx, t.Plan)
	}
	if e == nil {
		_, e = f.rotationLocked(ctx, t, p, expected, request, func() error {
			yes, e := f.policyReceipt(ctx, t, manager, false)
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
	return reconcileRotation(ctx, f, request, manager)
}

type rotationServiceManager interface {
	managedServiceManager
	activateManaged(context.Context, uint64, string, string) (bool, error)
}

func (f *filesystem) declaredRotation(t transaction, request string) (RotationPlan, uint64, error) {
	var p RotationPlan
	c, base, e := f.rotationBase(t)
	if e != nil {
		return p, 0, e
	}
	b, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
	if e == nil {
		i, e := gateway.DecodePolicyIntent(c, base, b)
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
	b, e = f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return p, 0, e
	}
	envelope, e := gateway.DecodeManagedEnvelope(c, b, base)
	if e != nil {
		return p, 0, e
	}
	if envelope.Revision < 2 || envelope.RequestID != request {
		return p, 0, ErrConflict
	}
	return RotationPlan{Version: 1, Policy: firecracker.Asset{Path: envelope.Source.Path, SHA256: envelope.Source.SHA256}}, envelope.ExpectedRevision, nil
}
func reconcileRotation(ctx context.Context, f *filesystem, request string, manager serviceManager) (Result, error) {
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
	t, e := f.readTransaction("commit")
	if e == nil {
		e = f.self(ctx, t.Plan)
	}
	var p RotationPlan
	var expected uint64
	var envelope gateway.PolicyEnvelope
	if e == nil {
		p, expected, e = f.declaredRotation(t, request)
	}
	if e == nil {
		envelope, e = f.rotationLocked(ctx, t, p, expected, request, nil)
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
	current, e := f.readTransaction("commit")
	if e != nil {
		return zero, e
	}
	if !bytes.Equal(encode(current), encode(t)) {
		return zero, ErrConflict
	}
	if e = f.verifyTransaction(ctx, t); e != nil {
		return zero, e
	}
	_, now, e := f.effectivePolicy(t, true)
	if e != nil {
		return zero, e
	}
	if now.Revision != envelope.Revision || now.RequestID != request || now.Source != envelope.Source {
		return zero, ErrConflict
	}
	yes, e = f.policyReceipt(ctx, t, manager, false)
	if e != nil {
		return zero, e
	}
	if !yes {
		return zero, ErrPlatform
	}
	if e = f.removePolicyIntent(t, request); e != nil {
		return zero, e
	}
	r, e := f.committedResult(t)
	if e != nil {
		return zero, e
	}
	r.ManagerReconciled = true
	return r, nil
}
func (f *filesystem) removePolicyIntent(t transaction, request string) error {
	c, base, e := f.rotationBase(t)
	if e != nil {
		return e
	}
	b, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
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
	intent, e := gateway.ValidateVisiblePolicyIntent(c, base, payload, b)
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
