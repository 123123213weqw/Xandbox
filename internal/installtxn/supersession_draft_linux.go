//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/123123213weqw/Xandbox/internal/gateway"
	"golang.org/x/sys/unix"
)

const supersessionDraft = ".policy-supersession.next"

type draftWork struct {
	config          gateway.Config
	base            string
	payload, intent []byte
	stat            *unix.Stat_t
}

func validDraftArguments(expected uint64, pending, sha string) bool {
	return expected > 0 && expected != ^uint64(0) && requestPattern.MatchString(pending) && digestPattern.MatchString(sha)
}

// This view grants no policy authority. A typed FUTURE ordinary rotation intent
// must still fence the exact installed predecessor. Recovery and committed
// supersession authority, and every other metadata scratch, refuse this path.
func (f *filesystem) prepareDraft(ctx context.Context, t transaction, expected uint64, pending, sha string) (*draftWork, error) {
	if !validDraftArguments(expected, pending, sha) {
		return nil, ErrPolicy
	}
	if pending == t.RequestID {
		return nil, ErrConflict
	}
	c, base, e := f.rotationBase(t)
	if e != nil {
		return nil, e
	}
	payload, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		return nil, e
	}
	p, e := gateway.DecodeManagedEnvelope(c, payload, base)
	if e != nil {
		return nil, e
	}
	intent, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
	if e != nil {
		return nil, e
	}
	i, e := gateway.DecodePolicyIntent(c, base, intent)
	if e != nil || p.Revision != expected || i.ExpectedRevision != expected || i.RequestID != pending || p.RequestID == pending || i.OldPayloadSHA256 != digest(payload) {
		return nil, ErrConflict
	}
	for _, name := range []string{".intent.next", ".commit.next", ".rotation-intent.next", "policy-recovery.json", ".policy-recovery.next", "policy-supersession.json"} {
		yes, e := f.exists(Root + "/" + name)
		if e != nil {
			return nil, e
		}
		if yes {
			return nil, ErrInventory
		}
	}
	// Proposal DATA may be missing, partial or opaque. It is bounded/private but
	// is never adopted, removed or rewritten by this operation.
	if _, e = f.readPrefix(Root+"/.policy.next", gateway.MaxSnapshotBytes); e != nil && !errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	override := File{Path: gateway.ManagedPolicyPath, SHA256: digest(payload), Bytes: int64(len(payload)), Mode: 0600}
	if e = f.verifyTargetsAgainst(ctx, t, false, &override); e != nil {
		return nil, e
	}
	stat, e := f.pinDraft(ctx, sha)
	if e != nil {
		return nil, e
	}
	return &draftWork{config: c, base: base, payload: payload, intent: intent, stat: stat}, nil
}

// Empty and partial drafts are valid *data* for an exact hash-bound discard,
// never a decoded authority. ENOENT is only a current-absence retry observation.
func (f *filesystem) pinDraft(ctx context.Context, sha string) (*unix.Stat_t, error) {
	in, e := f.open(Root+"/"+supersessionDraft, unix.O_RDONLY, 0600)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer in.Close()
	return draftStat(ctx, in, sha)
}

func draftStat(ctx context.Context, in *os.File, sha string) (*unix.Stat_t, error) {
	var s unix.Stat_t
	if trustedStat(int(in.Fd()), false, 0600) != nil || unix.Fstat(int(in.Fd()), &s) != nil || s.Size < 0 || s.Size > gateway.MaxPolicySupersession {
		return nil, ErrInventory
	}
	sum, e := hashFile(ctx, in, s.Size)
	if e != nil {
		return nil, e
	}
	if sum != sha {
		return nil, ErrConflict
	}
	var after unix.Stat_t
	if unix.Fstat(int(in.Fd()), &after) != nil {
		return nil, ErrInventory
	}
	s.Atim = after.Atim // our hash read may update access time, never content time
	if after != s {
		return nil, ErrInventory
	}
	return &after, nil
}

func sameDraft(a, b *unix.Stat_t) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size
}

func (f *filesystem) discardDraft(ctx context.Context, sha string, pinned *unix.Stat_t) (bool, error) {
	in, e := f.open(Root+"/"+supersessionDraft, unix.O_RDONLY, 0600)
	if errors.Is(e, unix.ENOENT) && pinned == nil {
		return false, f.syncDir(Root)
	}
	if e != nil {
		return false, e
	}
	defer in.Close()
	stat, e := draftStat(ctx, in, sha)
	if e != nil {
		return false, e
	}
	if !sameDraft(stat, pinned) {
		return false, ErrConflict
	}
	if e = f.point("supersession-draft-discard-ready"); e != nil {
		return false, e
	}
	// Rehash AFTER the last cut seam. A matching path/inode alone does not
	// establish content stability against a concurrent non-cooperating writer.
	stat, e = draftStat(ctx, in, sha)
	if e != nil || !sameDraft(stat, pinned) {
		return false, errors.Join(e, ErrConflict)
	}
	dir, e := f.directory(Root)
	if e != nil {
		return false, e
	}
	defer dir.Close()
	var now unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), supersessionDraft, &now, unix.AT_SYMLINK_NOFOLLOW) != nil || now != *stat {
		return false, ErrConflict
	}
	if e = unix.Unlinkat(int(dir.Fd()), supersessionDraft, 0); e != nil {
		return false, e
	}
	if e = f.point("supersession-draft-unlinked"); e != nil {
		return false, e
	}
	if e = dir.Sync(); e != nil {
		return false, e
	}
	return true, f.point("supersession-draft-durable")
}

func discardSupersessionDraftOperation(ctx context.Context, f *filesystem, expected uint64, pending, sha string, manager serviceManager, confirm policyAdvance) (DraftResult, error) {
	var zero DraftResult
	if !validDraftArguments(expected, pending, sha) {
		return zero, ErrPolicy
	}
	m, ok := manager.(recoveryServiceManager)
	if !ok || confirm == nil {
		return zero, ErrPlatform
	}
	done, e := f.operationLock(ctx, true)
	if e != nil {
		return zero, e
	}
	defer done()
	unlock, e := f.existingLock(ctx, true)
	if e != nil {
		return zero, e
	}
	t, e := f.readTransaction("commit")
	if e == nil {
		e = f.self(ctx, t.Plan)
	}
	var w *draftWork
	if e == nil {
		w, e = f.prepareDraft(ctx, t, expected, pending, sha)
	}
	unlock()
	if e != nil {
		return zero, e
	}
	removed := false
	e = m.maintainIngress(ctx, func() error {
		unlock, e := f.existingLock(ctx, true)
		if e != nil {
			return e
		}
		defer unlock()
		current, e := f.readTransaction("commit")
		if e != nil {
			return e
		}
		if !bytes.Equal(encode(current), encode(t)) {
			return ErrConflict
		}
		if e = f.self(ctx, t.Plan); e != nil {
			return e
		}
		fresh, e := f.prepareDraft(ctx, t, expected, pending, sha)
		if e != nil {
			return e
		}
		if fresh.base != w.base || !bytes.Equal(fresh.payload, w.payload) || !bytes.Equal(fresh.intent, w.intent) || !sameDraft(fresh.stat, w.stat) {
			return ErrConflict
		}
		auth, e := f.read(Root+"/auth.json", 65536, 0600)
		if e != nil {
			return e
		}
		if digest(auth) != t.Plan.Auth.SHA256 {
			return ErrInventory
		}
		// Exact EXISTING state only: no advance/bootstrap/collection/activation.
		if e = confirm(w.config, auth, w.payload, w.base); e != nil {
			return e
		}
		if e = f.point("supersession-draft-current-confirmed"); e != nil {
			return e
		}
		removed, e = f.discardDraft(ctx, sha, w.stat)
		if e != nil {
			return e
		}
		// A receipt is a new observation, not a historical abort journal. The
		// pending intent remains; ordinary startup MUST still fail closed.
		final, e := f.prepareDraft(ctx, t, expected, pending, sha)
		if e != nil {
			return e
		}
		if final.stat != nil || !bytes.Equal(final.payload, w.payload) || !bytes.Equal(final.intent, w.intent) {
			return ErrConflict
		}
		return f.point("supersession-draft-confirmed")
	})
	if e != nil {
		return zero, e
	}
	return DraftResult{Version: 1, Revision: expected, PendingRequestID: pending, RequestedDraftSHA256: sha, DraftRemoved: removed, DraftAbsent: true, IngressStopped: true}, nil
}

// DiscardSupersessionDraft has no root/path/service/source selector. It leaves
// the main service, policy, future intent and proposal DATA untouched and never
// restarts ingress. The public caller supplies ONLY the fixed state confirmer.
func DiscardSupersessionDraft(ctx context.Context, expected uint64, pending, sha string) (DraftResult, error) {
	if !validDraftArguments(expected, pending, sha) {
		return DraftResult{}, ErrPolicy
	}
	f, e := systemFS()
	if e != nil {
		return DraftResult{}, e
	}
	defer f.root.Close()
	return discardSupersessionDraftOperation(ctx, f, expected, pending, sha, systemManager{f, f.managerCommand}, gateway.ConfirmManagedPolicyState)
}
