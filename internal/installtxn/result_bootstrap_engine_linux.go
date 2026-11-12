//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
	"path/filepath"
)

type resultBootstrap struct {
	fs       *filesystem
	programs func(context.Context, Plan, Release) error
}

func newResultBootstrap(f *filesystem) resultBootstrap {
	return resultBootstrap{fs: f, programs: f.resultProgramBuilds}
}
func (p prepared) resultTransaction(request string) resultTransaction {
	t := resultTransaction{Version: 2, Revision: 1, RequestID: request, Plan: p.plan, Release: p.release}
	for _, v := range p.targets {
		t.Files = append(t.Files, v.file)
	}
	return t
}
func (f *filesystem) readResultTransaction(name string) (resultTransaction, error) {
	raw, e := f.read(Root+"/"+name+".json", 65536, 0600)
	if e != nil {
		return resultTransaction{}, e
	}
	return decodeResultTransaction(raw)
}

func (b resultBootstrap) commitPrepared(ctx context.Context, p *prepared, request string, pending bool) (resultTransaction, error) {
	f := b.fs
	t := p.resultTransaction(request)
	var zero resultTransaction
	if !validResultTransaction(t) {
		return zero, ErrPolicy
	}
	if pending {
		old, e := f.readResultTransaction("intent")
		if e != nil {
			return zero, e
		}
		if !bytes.Equal(encode(old), encode(t)) {
			return zero, ErrConflict
		}
	}
	if e := f.record("intent", encode(t)); e != nil {
		return zero, e
	}
	for _, d := range directories {
		mode := d.mode
		if d.path == childRoot {
			yes, e := f.exists(childRoot)
			if e != nil {
				return zero, e
			}
			if yes {
				dir, e := f.directory(childRoot)
				if e != nil {
					return zero, e
				}
				st, e := dir.Stat()
				dir.Close()
				if e != nil {
					return zero, e
				}
				if st.Mode().Perm() == 0555 {
					mode = 0555
				}
			}
		}
		if e := f.mkdir(d.path, mode); e != nil {
			return zero, e
		}
	}
	for _, v := range p.targets {
		if e := f.materialize(ctx, v); e != nil {
			return zero, e
		}
	}
	child, e := f.directory(childRoot)
	if e != nil {
		return zero, e
	}
	e = child.Chmod(0555)
	if e == nil {
		e = child.Sync()
	}
	child.Close()
	if e != nil {
		return zero, e
	}
	if e = f.syncDir(filepath.Dir(childRoot)); e != nil {
		return zero, e
	}
	// For validation before commit, the private intent is authoritative for this
	// exact request only; verifyTransaction never starts a manager or a guest.
	if e = b.verifyTargets(ctx, t, false); e != nil {
		return zero, e
	}
	if e = f.record("commit", encode(t)); e != nil {
		return zero, e
	}
	if e = f.point("commit-confirmed"); e != nil {
		return zero, e
	}
	if e = f.removeResultIntent(t); e != nil {
		return zero, e
	}
	return t, nil
}
func (b resultBootstrap) installLocked(ctx context.Context, plan Plan, request string, manager serviceManager, load func(context.Context, Plan, bool) (*prepared, func(), error)) (resultTransaction, error) {
	f := b.fs
	var zero resultTransaction
	if b.programs == nil || plan.Version != 2 || !requestPattern.MatchString(request) {
		return zero, ErrPolicy
	}
	if e := f.rootInventory(plan.Version, false); e != nil {
		return zero, e
	}
	if t, e := f.readResultTransaction("commit"); e == nil {
		if t.RequestID != request || !bytes.Equal(encode(t.Plan), encode(plan)) {
			return zero, ErrConflict
		}
		if e = b.verifyTargets(ctx, t, true); e != nil {
			return zero, e
		}
		if e = f.removeResultIntent(t); e != nil {
			return zero, e
		}
		return t, nil
	} else if !errors.Is(e, unix.ENOENT) {
		return zero, e
	}
	pending := false
	if t, e := f.readResultTransaction("intent"); e == nil {
		if t.RequestID != request || !bytes.Equal(encode(t.Plan), encode(plan)) {
			return zero, ErrConflict
		}
		pending = true
	} else if !errors.Is(e, unix.ENOENT) {
		return zero, e
	}
	p, close, e := load(ctx, plan, pending)
	if e != nil {
		return zero, e
	}
	defer close()
	if !pending {
		if e = f.initialInventory(p); e != nil {
			return zero, e
		}
		if e = manager.fresh(ctx); e != nil {
			return zero, e
		}
	}
	return b.commitPrepared(ctx, p, request, pending)
}
func (b resultBootstrap) effectivePolicy(t resultTransaction, committed bool) (File, gateway.PolicyEnvelope, error) {
	f := b.fs
	var zero File
	var envelope gateway.PolicyEnvelope
	if t.Plan.Version != 2 || t.Plan.Policy == nil {
		return zero, envelope, ErrPolicy
	}
	raw, e := f.read(Root+"/gateway.json", gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return zero, envelope, e
	}
	var c gateway.Config
	if strictjson.Decode(raw, &c) != nil || c.Version != 2 || c.InitialPolicySHA256 != t.Plan.Policy.SHA256 || digest(raw) != t.Plan.Gateway.SHA256 {
		return zero, envelope, ErrInventory
	}
	base, e := gateway.ValidateManagedResultBase(c, raw, encode(t))
	if e != nil {
		return zero, envelope, e
	}
	payload, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return zero, envelope, e
	}
	envelope, e = gateway.DecodeManagedEnvelope(c, payload, base)
	if e != nil {
		return zero, envelope, e
	}
	if !committed && envelope.Revision != 1 {
		return zero, envelope, ErrInventory
	}
	intent, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
	if e == nil {
		if !committed {
			return zero, envelope, ErrInventory
		}
		if _, e = gateway.ValidateVisiblePolicyIntent(c, base, payload, intent); e != nil {
			return zero, envelope, e
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return zero, envelope, e
	}
	recovery, e := f.read(Root+"/policy-recovery.json", gateway.MaxPolicyRecovery, 0600)
	if e == nil {
		if !committed {
			return zero, envelope, ErrInventory
		}
		if _, e = gateway.ValidateVisiblePolicyRecovery(c, base, payload, intent, recovery, false); e != nil {
			return zero, envelope, e
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return zero, envelope, e
	}
	supersession, e := f.read(Root+"/policy-supersession.json", gateway.MaxPolicySupersession, 0600)
	if e == nil {
		if !committed || len(recovery) != 0 {
			return zero, envelope, ErrInventory
		}
		if _, e = gateway.ValidateVisiblePolicySupersession(c, base, payload, intent, supersession); e != nil {
			return zero, envelope, e
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return zero, envelope, e
	}
	return File{Path: gateway.ManagedPolicyPath, SHA256: digest(payload), Bytes: int64(len(payload)), Mode: 0600}, envelope, nil
}

func (b resultBootstrap) verifyTargets(ctx context.Context, t resultTransaction, committed bool) error {
	f := b.fs
	if b.programs == nil || !validResultTransaction(t) {
		return ErrInventory
	}
	if e := f.rootInventory(t.Plan.Version, committed); e != nil {
		return e
	}
	var effective File
	var effectiveRevision uint64
	if t.Plan.Version == 2 {
		var e error
		var envelope gateway.PolicyEnvelope
		effective, envelope, e = b.effectivePolicy(t, committed)
		if e != nil {
			return e
		}
		effectiveRevision = envelope.Revision
	}
	var override *File
	if effectiveRevision > 1 {
		override = &effective
	}
	// The same private value already passed policy above; no caller callback
	// receives it during effectivePolicy. Keep the SECOND fresh root inventory
	// and every file/metadata check, not a cross-call validation/authority cache.
	return b.verifyTargetsAfterPolicy(ctx, t, committed, override)
}

func (b resultBootstrap) verifyTargetsAfterPolicy(ctx context.Context, t resultTransaction, committed bool, override *File) error {
	f := b.fs
	if e := f.rootInventory(t.Plan.Version, committed); e != nil {
		return e
	}
	if override != nil && (t.Plan.Version != 2 || override.Path != gateway.ManagedPolicyPath || override.Mode != 0600 || override.Bytes <= 0 || override.Bytes > gateway.MaxSnapshotBytes || !digestPattern.MatchString(override.SHA256)) {
		return ErrPolicy
	}
	if e := f.verifyFileSequence(ctx, t.Files, override); e != nil {
		return e
	}
	if e := b.verifyGenerated(t); e != nil {
		return e
	}
	// Immutable artifact and child-executable inventories are closed. Mutable
	// ledger/runtime/policy subtrees remain the ordinary driver's responsibility.
	names, e := f.names(assetDir)
	if e != nil {
		return e
	}
	expected := []string{}
	for _, r := range roles {
		if filepath.Dir(rolePath(r)) == assetDir {
			expected = append(expected, filepath.Base(rolePath(r)))
		}
	}
	sort.Strings(expected)
	if !sameNames(names, expected) {
		return ErrInventory
	}
	names, e = f.names(childRoot)
	if e != nil || !sameNames(names, []string{"gateway"}) {
		return ErrInventory
	}
	for _, v := range []struct {
		path string
		mode uint32
	}{{Root, 0700}, {DataRoot, 0700}, {assetDir, 0700}, {DataRoot + "/g", 0700}, {childRoot, 0555}} {
		dir, e := f.directory(v.path)
		if e != nil {
			return e
		}
		e = trustedStat(int(dir.Fd()), true, v.mode)
		dir.Close()
		if e != nil {
			return e
		}
	}
	if pending, e := f.readResultTransaction("intent"); e == nil {
		if !bytes.Equal(encode(pending), encode(t)) {
			return ErrInventory
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return e
	}
	if e = b.programs(ctx, t.Plan, t.Release); e != nil {
		return e
	}
	return f.syncDir(Root)
}
func (b resultBootstrap) verifyGenerated(t resultTransaction) error {
	f := b.fs
	plan := t.Plan
	art, e := descriptor(t.Release)
	if e != nil {
		return e
	}
	raw, e := f.read(Root+"/backend.json", 16384, 0600)
	if e != nil {
		return e
	}
	cfg, decodeErr := firecracker.DecodeInspectionConfig(raw)
	if decodeErr != nil || cfg.Version != 4 || cfg.Results == nil || !cfg.Results.Valid() || cfg.Snapshot != nil || cfg.RuntimeRoot != runtimeDir || cfg.CgroupRoot != unitRoot+"/node/instances" || cfg.IO == nil || cfg.Node == nil || cfg.Quota == nil {
		return ErrInventory
	}
	n := nodeManifest(plan, art)
	if cfg.Node.MaxInstances != n.Frontend.MaxInstances || cfg.Node.MaxRecords != n.Frontend.MaxRecords || cfg.Node.MaxSessions != n.Frontend.MaxSessions {
		return ErrInventory
	}
	contract, contractErr := launch.NewResultContract(n, *cfg.Results)
	if contractErr != nil || contract.CheckServiceBackend(cfg) != nil {
		return ErrInventory
	}
	for role, a := range map[string]firecracker.Asset{"firecracker": cfg.Firecracker, "jailer": cfg.Jailer, "warden": cfg.Warden, "kernel": cfg.Kernel, "initrd": cfg.Initrd, "workspace": cfg.Workspace} {
		if a.Path != rolePath(role) || a.SHA256 != art[role].SHA256 {
			return ErrInventory
		}
	}
	generated, e := renderResults(plan, cfg.IO.Device, art, *cfg.Results)
	if e != nil {
		return e
	}
	for path, data := range generated {
		if e = f.exact(path, data, 0600); e != nil {
			return e
		}
	}
	return nil
}

func (f *filesystem) removeResultIntent(tx resultTransaction) error {
	path := Root + "/intent.json"
	if e := f.exact(path, encode(tx), 0600); e != nil {
		if errors.Is(e, unix.ENOENT) {
			return nil
		}
		return e
	}
	dir, e := f.directory(Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = unix.Unlinkat(int(dir.Fd()), "intent.json", 0); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return f.point("intent-removed")
}
