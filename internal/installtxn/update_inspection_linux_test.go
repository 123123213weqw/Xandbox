//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/releasestore"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

// A shadow installation with structural ELF DATA, never usable/executed VMMs.
// The real anchored publisher reader and both 128 MiB workspace byte hashes
// run here; no manager, root operation, system service or VM runs in this test.
func inspectionFixture(t *testing.T, changeBackend bool) (*filesystem, transaction, UpdateInspectionPlan) {
	t.Helper()
	f, p, m := fixture(t)
	base := f.root.Name() + releasestore.Root
	if e := os.MkdirAll(base+"/objects", 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(base+"/.lock", nil, 0600); e != nil {
		t.Fatal(e)
	}
	previous := releaseFixture(t, f, false)
	previousID := digest(encode(previous))
	p.release, p.plan.Release = previous, previousID
	art, e := descriptor(previous)
	if e != nil {
		t.Fatal(e)
	}
	var cfg firecracker.Config
	for _, target := range p.targets {
		if target.file.Path == Root+"/backend.json" && strictjson.Decode(target.data, &cfg) != nil {
			t.Fatal("fixture backend")
		}
	}
	for role, a := range map[string]*firecracker.Asset{"firecracker": &cfg.Firecracker, "jailer": &cfg.Jailer, "warden": &cfg.Warden, "kernel": &cfg.Kernel, "initrd": &cfg.Initrd, "workspace": &cfg.Workspace} {
		a.SHA256 = art[role].SHA256
	}
	backend := encode(cfg)
	p.plan.Backend.SHA256 = digest(backend)
	generated, e := render(p.plan, "1:1", art)
	if e != nil {
		t.Fatal(e)
	}
	generated[Root+"/backend.json"] = backend
	for i := range p.targets {
		v := &p.targets[i]
		if b, ok := generated[v.file.Path]; ok {
			v.data, v.file.SHA256, v.file.Bytes = b, digest(b), int64(len(b))
		}
		for role, a := range art {
			if v.file.Path != rolePath(role) && !(role == "gateway" && v.file.Path == childRoot+"/gateway") {
				continue
			}
			mode := uint32(0400)
			if executable(role) {
				mode = 0500
			}
			in, e := f.open(releasestore.Root+"/objects/"+previousID+"/"+role, unix.O_RDONLY, mode)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { in.Close() })
			v.source, v.data, v.file.SHA256, v.file.Bytes = in, nil, a.SHA256, a.Bytes
		}
	}
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	// A distinct descriptor/daemon, optionally one changed backend-bound asset.
	// These structural fixtures remain data; no ELF is executed.
	next := inspectionCandidate(t, f, previous, changeBackend)
	nextID := digest(encode(next))
	ref := releasestore.Reference{Version: 1, Revision: 2, ExpectedRevision: 1, Release: nextID, Previous: previousID, RequestID: strings.Repeat("b", 32), IntentSHA256: strings.Repeat("b", 64)}
	if e := os.WriteFile(base+"/ref.json", encode(ref), 0600); e != nil {
		t.Fatal(e)
	}
	return f, tx, UpdateInspectionPlan{Version: 1, InstallCommitSHA256: digest(encode(tx)), ReleaseRevision: 2, CandidateRelease: nextID, RetainedRelease: previousID}
}

func inspectionCandidate(t *testing.T, f *filesystem, previous Release, changeBackend bool) Release {
	t.Helper()
	base := f.root.Name() + "/update-staging"
	if e := os.Mkdir(base, 0700); e != nil {
		t.Fatal(e)
	}
	next := previous
	next.SourceRevision = strings.Repeat("b", 40)
	next.Files = append([]Artifact(nil), previous.Files...)
	previousID := digest(encode(previous))
	for i, a := range next.Files {
		b := []byte("model-asset")
		mode := os.FileMode(0400)
		if a.Role != "workspace" {
			var e error
			b, e = os.ReadFile(f.root.Name() + releasestore.Root + "/objects/" + previousID + "/" + a.Role)
			if e != nil {
				t.Fatal(e)
			}
			if a.Role == "daemon" || changeBackend && a.Role == "kernel" {
				b[len(b)-1] ^= 1
			}
			next.Files[i].SHA256 = digest(b)
		}
		if executable(a.Role) {
			mode = 0500
		}
		path := base + "/" + a.Role
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		if a.Role == "workspace" {
			if e := os.Truncate(path, 128<<20); e != nil {
				t.Fatal(e)
			}
		}
		if e := os.Chmod(path, mode); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(base+"/manifest.json", encode(next), 0400); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(base, f.root.Name()+releasestore.Root+"/objects/"+digest(encode(next))); e != nil {
		t.Fatal(e)
	}
	return next
}

func TestUpdateInspectionRealReaderBothBundlesNoAuthorityOrServiceChanges(t *testing.T) {
	for _, changeBackend := range []bool{false, true} {
		name := "daemon-only"
		if changeBackend {
			name = "changed-binding"
		}
		t.Run(name, func(t *testing.T) {
			f, _, p := inspectionFixture(t, changeBackend)
			paths := []string{Root + "/commit.json", releasestore.Root + "/ref.json", stateDir + "/test-ledger", runtimeDir + "/test-owner", policyDir + "/test-revocation"}
			for _, path := range paths[2:] {
				if e := os.WriteFile(f.root.Name()+path, []byte("later-authority-must-not-rewind"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := map[string][]byte{}
			for _, path := range paths {
				b, e := os.ReadFile(f.root.Name() + path)
				if e != nil {
					t.Fatal(e)
				}
				before[path] = b
			}
			locks := map[string]os.FileInfo{}
			for _, path := range []string{Root + "/.lock", releasestore.Root + "/.lock"} {
				info, e := os.Stat(f.root.Name() + path)
				if e != nil {
					t.Fatal(e)
				}
				locks[path] = info
			}
			f.hook = func(stage string) error {
				if stage != "operation-lock-opened" && stage != "operation-lock-acquired" {
					t.Fatalf("read-only inspection entered persistence stage %s", stage)
				}
				return nil
			}
			got, e := f.inspectUpdate(context.Background(), p)
			if e != nil {
				t.Fatal(e)
			}
			changed, bound := 1, 0
			if changeBackend {
				changed, bound = 2, 1
			}
			expected := UpdateInspectionResult{Version: 1, InstalledFilesVerified: true, CandidateReleaseVerified: true, CurrentReleaseRetained: true, ChangedArtifacts: changed, ChangedBackendAssets: bound}
			if got != expected {
				t.Fatal("artifact verification inflated into compatibility/activation/health proof", got)
			}
			for path, b := range before {
				after, e := os.ReadFile(f.root.Name() + path)
				if e != nil || !bytes.Equal(after, b) {
					t.Fatal("installed or later authority changed", path, e)
				}
			}
			for path, info := range locks {
				after, e := os.Stat(f.root.Name() + path)
				if e != nil || !os.SameFile(info, after) || after.Size() != 0 {
					t.Fatal("original lock replaced", e)
				}
			}
		})
	}
}

func TestUpdateInspectionRejectsDriftPendingAndIncorrectReleasePins(t *testing.T) {
	f, _, p := inspectionFixture(t, false)
	for _, kind := range []string{"commit-pin", "release-revision", "retained-pin", "candidate-pin", "policy-pin", "pending", "scratch", "unknown", "installed-bytes", "retained-bytes", "candidate-bytes", "publisher-lock"} {
		t.Run(kind, func(t *testing.T) {
			plan := p
			var undo func()
			switch kind {
			case "commit-pin":
				plan.InstallCommitSHA256 = strings.Repeat("d", 64)
			case "release-revision":
				plan.ReleaseRevision++
			case "retained-pin":
				plan.RetainedRelease = strings.Repeat("d", 64)
			case "candidate-pin":
				plan.CandidateRelease = strings.Repeat("d", 64)
			case "policy-pin":
				plan.PolicyRevision, plan.PolicySHA256 = 1, strings.Repeat("d", 64)
			case "pending", "scratch", "unknown":
				name := map[string]string{"pending": "intent.json", "scratch": ".policy.next", "unknown": "foreign"}[kind]
				path := f.root.Name() + Root + "/" + name
				if e := os.WriteFile(path, []byte("preserve-unfinished-transaction"), 0600); e != nil {
					t.Fatal(e)
				}
				undo = func() {
					if e := os.Remove(path); e != nil {
						t.Error(e)
					}
				}
			case "installed-bytes", "retained-bytes", "candidate-bytes":
				path, mode := f.root.Name()+Root+"/auth.json", os.FileMode(0600)
				if kind != "installed-bytes" {
					id := p.RetainedRelease
					if kind == "candidate-bytes" {
						id = p.CandidateRelease
					}
					path, mode = f.root.Name()+releasestore.Root+"/objects/"+id+"/kernel", 0400
				}
				old, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.Chmod(path, 0600); e != nil {
					t.Fatal(e)
				}
				changed := append([]byte(nil), old...)
				changed[0] ^= 1
				if e = os.WriteFile(path, changed, 0600); e != nil {
					t.Fatal(e)
				}
				if e = os.Chmod(path, mode); e != nil {
					t.Fatal(e)
				}
				undo = func() {
					if e := os.Chmod(path, 0600); e != nil {
						t.Error(e)
						return
					}
					if e := os.WriteFile(path, old, 0600); e != nil {
						t.Error(e)
					}
					if e := os.Chmod(path, mode); e != nil {
						t.Error(e)
					}
				}
			case "publisher-lock":
				path := f.root.Name() + releasestore.Root + "/.lock"
				if e := os.Rename(path, path+".test-held"); e != nil {
					t.Fatal(e)
				}
				undo = func() {
					if e := os.Rename(path+".test-held", path); e != nil {
						t.Error(e)
					}
				}
			}
			if undo != nil {
				defer undo()
			}
			got, e := f.inspectUpdate(context.Background(), plan)
			if e == nil || got != (UpdateInspectionResult{}) {
				t.Fatal("partial inspection produced a successful receipt", kind, got, e)
			}
			if kind == "publisher-lock" {
				if _, e := os.Lstat(f.root.Name() + releasestore.Root + "/.lock"); !os.IsNotExist(e) {
					t.Fatal("reader created a replacement publisher lock", e)
				}
			}
		})
	}
	if _, e := f.inspectUpdate(context.Background(), p); e != nil {
		t.Fatal("controls failed to restore only their test-owned mutations", e)
	}
}

func TestUpdateInspectionNoMissingLockCreation(t *testing.T) {
	f, _, _ := fixture(t)
	if _, e := f.inspectUpdate(context.Background(), sampleUpdateInspection()); e == nil {
		t.Fatal("absent install accepted")
	}
	if yes, e := f.exists(Root + "/.lock"); e != nil || yes {
		t.Fatal("inspection created permanent lock", e)
	}
}

func TestUpdateInspectionBasePinsCurrentManagedPolicyNotAnOldBackup(t *testing.T) {
	f, tx, source := rotationFixture(t, false)
	p := sampleUpdateInspection()
	p.InstallCommitSHA256, p.RetainedRelease = digest(encode(tx)), tx.Plan.Release
	file, envelope, e := f.effectivePolicy(tx, true)
	if e != nil {
		t.Fatal(e)
	}
	p.PolicyRevision, p.PolicySHA256 = envelope.Revision, file.SHA256
	if _, e = f.inspectionBase(context.Background(), p); e != nil {
		t.Fatal("current v2 policy rejected", e)
	}
	old := p
	req := strings.Repeat("b", 32)
	if _, e = rotateModel(context.Background(), f, tx, source, 1, req, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = f.inspectionBase(context.Background(), old); e == nil {
		t.Fatal("pending policy accepted")
	}
	// Settle only this shadow file-transaction model. No real policy ACK or
	// health claim follows; the production inspection never calls this method.
	if e = f.removePolicyIntent(tx, req); e != nil {
		t.Fatal(e)
	}
	if _, e = f.inspectionBase(context.Background(), old); !errors.Is(e, ErrConflict) {
		t.Fatal("stale policy pin accepted after rotation", e)
	}
	file, envelope, e = f.effectivePolicy(tx, true)
	if e != nil {
		t.Fatal(e)
	}
	p.PolicyRevision, p.PolicySHA256 = envelope.Revision, file.SHA256
	before, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.inspectionBase(context.Background(), p); e != nil {
		t.Fatal("current rotated policy cannot be inventoried", e)
	}
	after, e := f.read(gateway.ManagedPolicyPath, gateway.MaxSnapshotBytes, 0600)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("policy history changed", e)
	}
}

func TestUpdateInspectionLocksCannotBeBypassedByCanceledCaller(t *testing.T) {
	f, p, m := fixture(t)
	if _, e := applyModel(context.Background(), f, p, request(), m); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"operation", "file"} {
		t.Run(kind, func(t *testing.T) {
			var unlock func()
			var e error
			if kind == "operation" {
				unlock, e = f.operationLock(context.Background(), true)
			} else {
				unlock, e = f.existingLock(context.Background(), true)
			}
			if e != nil {
				t.Fatal(e)
			}
			defer unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if _, e = f.inspectUpdate(ctx, sampleUpdateInspection()); !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal("original lock bypassed", e)
			}
		})
	}
}
