//go:build linux

package installtxn

import (
	"bytes"
	"context"

	"github.com/123123213weqw/Xandbox/internal/releasestore"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// InspectUpdate is read-only. It neither requires nor establishes that this
// inspecting binary is the installed self-pinned installer. The installed self
// file is still checked against the original commit like every other target.
// No manager is constructed, and no candidate program is executed.
func InspectUpdate(ctx context.Context, path string) (UpdateInspectionResult, error) {
	f, e := systemFS()
	if e != nil {
		return UpdateInspectionResult{}, e
	}
	defer f.root.Close()
	raw, e := f.read(path, MaxPlan, 0600)
	if e != nil {
		return UpdateInspectionResult{}, e
	}
	p, e := DecodeUpdateInspection(raw)
	if e != nil {
		return UpdateInspectionResult{}, e
	}
	return f.inspectUpdate(ctx, p)
}

func (f *filesystem) inspectionBase(ctx context.Context, p UpdateInspectionPlan) (transaction, error) {
	t, e := f.readTransaction("commit")
	if e != nil {
		return transaction{}, e
	}
	if digest(encode(t)) != p.InstallCommitSHA256 || t.Plan.Release != p.RetainedRelease || t.Plan.ReleaseRevision >= p.ReleaseRevision {
		return transaction{}, ErrConflict
	}
	// Even an otherwise recognized/recoverable intent is not a quiescent
	// installation inventory. Inspection must never remove/reconcile it.
	names, e := f.names(Root)
	if e != nil {
		return transaction{}, e
	}
	expected := map[string]bool{".lock": true, "commit.json": true}
	for _, name := range configNamesFor(t.Plan.Version) {
		expected[name] = true
	}
	if len(names) != len(expected) {
		return transaction{}, ErrInventory
	}
	for _, name := range names {
		if !expected[name] {
			return transaction{}, ErrInventory
		}
	}
	for _, root := range []string{runtimeFilesRoot, runtimeDrainRoot, runtimeStopRoot} {
		if yes, err := f.exists(root); err != nil {
			return transaction{}, err
		} else if yes {
			return transaction{}, ErrInventory
		}
	}
	if e = f.verifyTransaction(ctx, t); e != nil {
		return transaction{}, e
	}
	if t.Plan.Version == 1 {
		if p.PolicyRevision != 0 || p.PolicySHA256 != "" {
			return transaction{}, ErrConflict
		}
	} else {
		file, envelope, e := f.effectivePolicy(t, true)
		if e != nil {
			return transaction{}, e
		}
		if envelope.Revision != p.PolicyRevision || file.SHA256 != p.PolicySHA256 {
			return transaction{}, ErrConflict
		}
	}
	return t, nil
}

func (f *filesystem) inspectUpdate(ctx context.Context, p UpdateInspectionPlan) (UpdateInspectionResult, error) {
	var zero UpdateInspectionResult
	if _, e := DecodeUpdateInspection(encode(p)); e != nil {
		return zero, e
	}
	// Follow the existing lock order. OFD SH excludes exclusive maintenance;
	// file SH freezes ordinary install/policy commits. Neither creates a lock.
	operationDone, e := f.operationLock(ctx, false)
	if e != nil {
		return zero, e
	}
	defer operationDone()
	unlock, e := f.existingLock(ctx, false)
	if e != nil {
		return zero, e
	}
	defer unlock()
	t, e := f.inspectionBase(ctx, p)
	if e != nil {
		return zero, e
	}
	selection := t.Plan
	selection.ReleaseRevision, selection.Release = p.ReleaseRevision, p.CandidateRelease
	// The original reader holds the publisher's original EX lock, validates
	// BOTH retained bundles and native static ELF, and keeps candidate FDs open.
	view, e := f.release(ctx, selection, false)
	if e != nil {
		return zero, e
	}
	defer view.close()
	raw, e := f.read(releasestore.Root+"/ref.json", MaxPlan, 0600)
	if e != nil {
		return zero, e
	}
	var ref releasestore.Reference
	if strictjson.Decode(raw, &ref) != nil || !bytes.Equal(raw, encode(ref)) || ref.Revision != p.ReleaseRevision || ref.Release != p.CandidateRelease || ref.Previous != p.RetainedRelease {
		return zero, ErrConflict
	}
	old, e := descriptor(t.Release)
	if e != nil {
		return zero, e
	}
	r := UpdateInspectionResult{Version: 1, InstalledFilesVerified: true, CandidateReleaseVerified: true, CurrentReleaseRetained: true}
	for _, role := range roles {
		if old[role] != view.artifact[role] {
			r.ChangedArtifacts++
			switch role {
			case "firecracker", "jailer", "warden", "kernel", "initrd", "workspace":
				r.ChangedBackendAssets++
			}
		}
	}
	// Repeat installed byte/policy/commit proof under BOTH original locks.
	// Mutable ledger/session/node/catalog authority is deliberately not opened,
	// restored, replaced, claimed frozen or certified readable by either ELF.
	after, e := f.inspectionBase(ctx, p)
	if e != nil {
		return zero, e
	}
	if !bytes.Equal(encode(after), encode(t)) {
		return zero, ErrConflict
	}
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	return r, nil
}
