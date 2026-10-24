//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/gateway"
)

// Real anchored files, fsync, unlink, OFD/flock; MODELED stopped ingress/current
// state. These tests do NOT qualify the root CLI, kernel emptiness, TLS or KVM.
func draftFixture(t *testing.T, raw []byte) (*filesystem, transaction, *recoveryModelManager, *supModel, string, string, policyAdvance) {
	t.Helper()
	f, tx, p, m, state, _, pending, _, confirm := supFixture(t, false)
	if e := os.Remove(f.root.Name() + p.Policy.Path); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(f.root.Name()+Root+"/"+supersessionDraft, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return f, tx, m, state, pending, digest(raw), confirm
}

func draftRootBytes(t *testing.T, f *filesystem) map[string][]byte {
	t.Helper()
	names, e := f.names(Root)
	if e != nil {
		t.Fatal(e)
	}
	m := map[string][]byte{}
	for _, n := range names {
		b, e := os.ReadFile(f.root.Name() + Root + "/" + n)
		if e != nil {
			t.Fatal(e)
		}
		m[n] = b
	}
	return m
}

func assertDraftFence(t *testing.T, f *filesystem, tx transaction, before map[string][]byte) {
	t.Helper()
	if f.verifyTransaction(context.Background(), tx) == nil {
		t.Fatal("scratch removal bypassed the typed FUTURE intent startup fence")
	}
	for name, b := range before {
		if name == supersessionDraft {
			continue
		}
		after, e := os.ReadFile(f.root.Name() + Root + "/" + name)
		if e != nil || !bytes.Equal(after, b) {
			t.Fatal("non-draft content changed", name, e)
		}
	}
}

func TestSupersessionDraftSourceFreeDiscardIsNotPolicyCommitOrHistoricalReceipt(t *testing.T) {
	for name, raw := range map[string][]byte{"empty": {}, "partial": []byte(`{"version":1,"request`), "opaque": []byte("not an authority\x00")} {
		t.Run(name, func(t *testing.T) {
			f, tx, m, state, pending, sha, confirm := draftFixture(t, raw)
			before := draftRootBytes(t, f)
			out, e := discardSupersessionDraftOperation(context.Background(), f, 1, pending, sha, m, confirm)
			if e != nil || out.Version != 1 || out.Revision != 1 || out.PendingRequestID != pending || out.RequestedDraftSHA256 != sha || !out.DraftRemoved || !out.DraftAbsent || !out.IngressStopped || out.ProductionReady {
				t.Fatal("current absence receipt", out, e)
			}
			if state.high != 1 || state.advances != 0 || state.confirms != 1 || m.activationCalls != 0 || m.maintenanceCalls != 1 {
				t.Fatal("discard advanced policy or activated ingress")
			}
			assertDraftFence(t, f, tx, before)
			out, e = discardSupersessionDraftOperation(context.Background(), f, 1, pending, digest([]byte("a different requested hash")), m, confirm)
			if e != nil || out.DraftRemoved || !out.DraftAbsent || state.confirms != 2 {
				t.Fatal("absent retry fabricated historical hash/removal receipt", e)
			}
			// Only a NEW valid normal replacement can consume N+1. No abandoned
			// source or key was restored to perform the discard itself.
			p := supSource(t, f, tx, "/bootstrap/new-after-discard.json", 2)
			advance, confirm := supPrimitives(t, f, tx, m, state)
			res, e := supersessionOperation(context.Background(), f, p, 1, strings.Repeat("e", 32), pending, m, advance, confirm)
			if e != nil || res.Revision != 2 || !res.ManagerReconciled || state.high != 1 || state.advances != 0 {
				t.Fatal("ordinary future replacement did not remain mandatory", e)
			}
		})
	}
}

func TestSupersessionDraftCompleteUncommittedBytesAreNotAdopted(t *testing.T) {
	f, tx, p, m, state, n, pending, _, confirm := supFixture(t, false)
	w, e := f.prepareSupersession(context.Background(), tx, p, n, strings.Repeat("d", 32), pending, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw := encode(w.record)
	if e = os.WriteFile(f.root.Name()+Root+"/"+supersessionDraft, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(f.root.Name() + p.Policy.Path); e != nil {
		t.Fatal(e)
	}
	before := draftRootBytes(t, f)
	out, e := discardSupersessionDraftOperation(context.Background(), f, n, pending, digest(raw), m, confirm)
	if e != nil || !out.DraftRemoved || state.high != n || state.advances != 0 || m.activationCalls != 0 {
		t.Fatal("complete draft became authority", e)
	}
	assertDraftFence(t, f, tx, before)
	if yes, e := f.exists(Root + "/policy-supersession.json"); e != nil || yes {
		t.Fatal("committed declaration invented", e)
	}
}

func TestSupersessionDraftAlreadyPublishedEpochCannotBeReopened(t *testing.T) {
	f, tx, p := rotationFixture(t, true)
	pending := strings.Repeat("b", 32)
	if _, e := rotateModel(context.Background(), f, tx, p, 1, pending, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	raw := []byte("uncommitted data cannot rewind consumed file epoch")
	if e := os.WriteFile(f.root.Name()+Root+"/"+supersessionDraft, raw, 0600); e != nil {
		t.Fatal(e)
	}
	m := &recoveryModelManager{rotationModelManager: &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}}}, t: t, fs: f}
	state := &supModel{high: 1}
	_, confirm := supPrimitives(t, f, tx, m, state)
	for _, n := range []uint64{1, 2} {
		out, e := discardSupersessionDraftOperation(context.Background(), f, n, pending, digest(raw), m, confirm)
		if e == nil || out != (DraftResult{}) || m.maintenanceCalls != 0 || state.confirms != 0 {
			t.Fatal("published epoch accepted as unconsumed", n, e)
		}
	}
}

func TestSupersessionDraftRefusesUnknownAuthorityInventoryAndWrongCASBeforeMaintenance(t *testing.T) {
	for _, kind := range []string{"revision", "pending", "hash", "bad-hash", "max", "zero", "initial-id", "missing-intent", "malformed-intent", "wrong-predecessor", "consumed", "recovery", "committed-supersession", "intent-scratch", "commit-scratch", "rotation-scratch", "recovery-scratch", "unknown", "immutable", "extra-asset", "self", "mode", "link", "symlink", "directory", "oversize", "proposal-mode", "proposal-oversize", "lost-lock"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, m, state, pending, sha, confirm := draftFixture(t, []byte("opaque known draft"))
			n := uint64(1)
			path := f.root.Name() + Root + "/" + supersessionDraft
			write := func(name string, b []byte) {
				t.Helper()
				if e := os.WriteFile(f.root.Name()+Root+"/"+name, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "revision":
				n = 2
			case "pending":
				pending = strings.Repeat("f", 32)
			case "hash":
				sha = digest([]byte("wrong"))
			case "bad-hash":
				sha = strings.Repeat("A", 64)
			case "max":
				n = ^uint64(0)
			case "zero":
				n = 0
			case "initial-id":
				pending = tx.RequestID
			case "missing-intent":
				if e := os.Remove(f.root.Name() + Root + "/rotation-intent.json"); e != nil {
					t.Fatal(e)
				}
			case "malformed-intent":
				write("rotation-intent.json", []byte(`{"version":`))
			case "wrong-predecessor", "consumed":
				c, base, e := f.rotationBase(tx)
				if e != nil {
					t.Fatal(e)
				}
				b, e := f.read(Root+"/rotation-intent.json", gateway.MaxPolicyIntent, 0600)
				if e != nil {
					t.Fatal(e)
				}
				i, e := gateway.DecodePolicyIntent(c, base, b)
				if e != nil {
					t.Fatal(e)
				}
				if kind == "wrong-predecessor" {
					i.OldPayloadSHA256 = digest([]byte("different base"))
				} else {
					i.ExpectedRevision = 2
				}
				write("rotation-intent.json", encode(i))
			case "recovery":
				write("policy-recovery.json", []byte("not adoptable"))
			case "committed-supersession":
				write("policy-supersession.json", []byte("not adoptable"))
			case "intent-scratch":
				write(".intent.next", []byte("partial"))
			case "commit-scratch":
				write(".commit.next", []byte("partial"))
			case "rotation-scratch":
				write(".rotation-intent.next", []byte("partial"))
			case "recovery-scratch":
				write(".policy-recovery.next", []byte("partial"))
			case "unknown":
				write("unknown", []byte("partial"))
			case "immutable":
				write("auth.json", []byte("different auth"))
			case "extra-asset":
				if e := os.WriteFile(f.root.Name()+assetDir+"/extra", []byte("x"), 0600); e != nil {
					t.Fatal(e)
				}
			case "self":
				tx.Plan.Self.SHA256 = digest([]byte("not this ELF"))
				write("commit.json", encode(tx))
			case "mode":
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
			case "link":
				if e := os.Link(path, f.root.Name()+"/alias"); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(path, f.root.Name()+"/original"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(f.root.Name()+"/original", path); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "oversize":
				b := bytes.Repeat([]byte("x"), gateway.MaxPolicySupersession+1)
				write(supersessionDraft, b)
				sha = digest(b)
			case "proposal-mode":
				if e := os.Chmod(f.root.Name()+Root+"/.policy.next", 0644); e != nil {
					t.Fatal(e)
				}
			case "proposal-oversize":
				write(".policy.next", bytes.Repeat([]byte("x"), gateway.MaxSnapshotBytes+1))
			case "lost-lock":
				if e := os.Remove(f.root.Name() + Root + "/.lock"); e != nil {
					t.Fatal(e)
				}
			}
			before, e := os.Lstat(path)
			if e != nil {
				t.Fatal(e)
			}
			out, e := discardSupersessionDraftOperation(context.Background(), f, n, pending, sha, m, confirm)
			after, statErr := os.Lstat(path)
			if e == nil || out != (DraftResult{}) || statErr != nil || !os.SameFile(before, after) || state.confirms != 0 || state.advances != 0 || m.maintenanceCalls != 0 {
				t.Fatal("invalid precondition changed draft or reached maintenance", e, statErr)
			}
		})
	}
}

func TestSupersessionDraftRevalidatesAfterStopAndFailsClosedOnMissingCurrentState(t *testing.T) {
	for _, kind := range []string{"replace-inode", "mutate-draft", "remove-draft", "intent", "policy", "immutable", "confirm-refused", "nil-confirm"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, m, state, pending, sha, confirm := draftFixture(t, []byte("opaque known draft"))
			path := f.root.Name() + Root + "/" + supersessionDraft
			m.beforeWork = func() {
				switch kind {
				case "replace-inode":
					if e := os.Rename(path, f.root.Name()+"/old-draft"); e != nil {
						t.Fatal(e)
					}
					if e := os.WriteFile(path, []byte("opaque known draft"), 0600); e != nil {
						t.Fatal(e)
					}
				case "mutate-draft":
					if e := os.WriteFile(path, []byte("different"), 0600); e != nil {
						t.Fatal(e)
					}
				case "remove-draft":
					if e := os.Remove(path); e != nil {
						t.Fatal(e)
					}
				case "intent", "policy", "immutable":
					name := map[string]string{"intent": "rotation-intent.json", "policy": "gateway-policy.json", "immutable": "auth.json"}[kind]
					if e := os.WriteFile(f.root.Name()+Root+"/"+name, []byte("changed after stop"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			if kind == "confirm-refused" {
				confirm = func(gateway.Config, []byte, []byte, string) error { return ErrConflict }
			}
			if kind == "nil-confirm" {
				confirm = nil
			}
			out, e := discardSupersessionDraftOperation(context.Background(), f, 1, pending, sha, m, confirm)
			if e == nil || out != (DraftResult{}) || state.high != 1 || state.advances != 0 || m.activationCalls != 0 {
				t.Fatal("post-stop refusal made a policy receipt", e)
			}
			if kind != "remove-draft" {
				if _, e := os.Lstat(path); e != nil {
					t.Fatal("refusal discarded draft", e)
				}
			}
			if kind == "nil-confirm" && m.maintenanceCalls != 0 {
				t.Fatal("nil confirmer stopped ingress")
			}
			_ = tx
		})
	}
}

var draftStages = []string{"supersession-draft-current-confirmed", "supersession-draft-discard-ready", "supersession-draft-unlinked", "supersession-draft-durable", "supersession-draft-confirmed"}

func TestSupersessionDraftEveryErrorBoundaryLeavesFutureFenceAndCurrentAbsenceRetry(t *testing.T) {
	for _, stage := range draftStages {
		t.Run(stage, func(t *testing.T) {
			f, tx, m, state, pending, sha, confirm := draftFixture(t, []byte("partial declaration"))
			before := draftRootBytes(t, f)
			hit := false
			f.hook = func(at string) error {
				if at == stage {
					hit = true
					return interrupted
				}
				return nil
			}
			if out, e := discardSupersessionDraftOperation(context.Background(), f, 1, pending, sha, m, confirm); !hit || !errors.Is(e, interrupted) || out != (DraftResult{}) {
				t.Fatal("fault not reached/receipt escaped", e)
			}
			assertDraftFence(t, f, tx, before)
			f.hook = nil
			root, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			fresh := &filesystem{root: root}
			m.fs = fresh
			_, confirm = supPrimitives(t, fresh, tx, m, state)
			out, e := discardSupersessionDraftOperation(context.Background(), fresh, 1, pending, sha, m, confirm)
			wantRemoved := stage == draftStages[0] || stage == draftStages[1]
			if e != nil || out.DraftRemoved != wantRemoved || !out.DraftAbsent || state.high != 1 || state.advances != 0 {
				t.Fatal("fresh absence retry", out, e)
			}
			assertDraftFence(t, fresh, tx, before)
		})
	}
}

func TestSupersessionDraftLastMomentCASRehashesAndNeverUnlinksReplacement(t *testing.T) {
	for _, kind := range []string{"same-inode-content", "replacement-inode", "hardlink", "mode"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, m, _, pending, sha, confirm := draftFixture(t, []byte("opaque known draft"))
			before := draftRootBytes(t, f)
			path := f.root.Name() + Root + "/" + supersessionDraft
			f.hook = func(at string) error {
				if at != "supersession-draft-discard-ready" {
					return nil
				}
				switch kind {
				case "same-inode-content":
					return os.WriteFile(path, []byte("different contents"), 0600)
				case "replacement-inode":
					if e := os.Rename(path, filepath.Join(f.root.Name(), "other")); e != nil {
						return e
					}
					return os.WriteFile(path, []byte("opaque known draft"), 0600)
				case "hardlink":
					return os.Link(path, filepath.Join(f.root.Name(), "alias"))
				case "mode":
					return os.Chmod(path, 0644)
				}
				return nil
			}
			out, e := discardSupersessionDraftOperation(context.Background(), f, 1, pending, sha, m, confirm)
			if e == nil || out != (DraftResult{}) {
				t.Fatal("last moment mutation accepted")
			}
			if _, e = os.Lstat(path); e != nil {
				t.Fatal("replacement unlinked", e)
			}
			assertDraftFence(t, f, tx, before)
		})
	}
}

func TestSupersessionDraftOriginalOperationLockExcludesCompetingMutations(t *testing.T) {
	f, tx, m, _, pending, sha, confirm := draftFixture(t, []byte("partial declaration"))
	checked := false
	m.beforeWork = func() {
		for _, exclusive := range []bool{false, true} {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			done, e := f.operationLock(ctx, exclusive)
			cancel()
			if e == nil {
				done()
				t.Fatal("competing operation acquired original lock")
			}
			if !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal("wrong contention result", e)
			}
		}
		gate, e := f.existingLock(context.Background(), false)
		if e != nil {
			t.Fatal(e)
		}
		gate()
		checked = true
	}
	if _, e := discardSupersessionDraftOperation(context.Background(), f, 1, pending, sha, m, confirm); e != nil || !checked {
		t.Fatal("lock ordering", e)
	}
	if f.verifyTransaction(context.Background(), tx) == nil {
		t.Fatal("gate no longer fenced")
	}
}
