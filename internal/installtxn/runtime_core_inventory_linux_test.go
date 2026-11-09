//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"golang.org/x/sys/unix"
)

func seedCoreModel(t *testing.T, x *stopTestModel) (sandbox.Record, session.Record) {
	t.Helper()
	now := time.Now().UTC()
	r := sandbox.Record{Ref: sandbox.Ref{ID: runtimeReq("1"), Generation: runtimeReq("2")}, Backend: "firecracker", TenantID: "tenant-a", CreateKeyHash: strings.Repeat("3", 64), CreateSpecHash: strings.Repeat("4", 64), State: sandbox.Destroyed, DeleteRequested: true, Limits: sandbox.Limits{MaxExecMS: 1000, MaxOutputBytes: 4096, MaxJobs: 16}, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour), StoppedAt: now, DestroyedAt: now}
	j := session.Record{ID: runtimeReq("5"), TenantID: r.TenantID, CreateKeyHash: strings.Repeat("6", 64), CreateSpecHash: strings.Repeat("7", 64), Revision: 1, Current: r.Ref, State: session.Closed, CreatedAt: now, UpdatedAt: now, Attempts: []session.Attempt{{KeyHash: strings.Repeat("6", 64), SpecHash: strings.Repeat("7", 64), ResultRevision: 1, Target: r.Ref, State: "COMMITTED", StartedAt: now, ReadyAt: now, FencedAt: now, CommitStartedAt: now}}}
	for _, name := range []string{"ledger", "sessions"} {
		if e := os.MkdirAll(x.f.root.Name()+stateDir+"/"+name, 0700); e != nil {
			t.Fatal(e)
		}
	}
	writeCoreModel(t, x, "ledger", r.ID, r)
	writeCoreModel(t, x, "sessions", j.ID, j)
	return r, j
}
func writeCoreModel(t *testing.T, x *stopTestModel, dir, id string, r any) {
	t.Helper()
	b, e := json.Marshal(struct {
		Version int `json:"version"`
		Record  any `json:"record"`
	}{1, r})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(x.f.root.Name()+stateDir+"/"+dir+"/"+id+".json", b, 0600); e != nil {
		t.Fatal(e)
	}
}
func stoppedCoreModel(t *testing.T) (*stopTestModel, *runtimeScope) {
	t.Helper()
	x := stopModel(t, "")
	s := x.scope(t)
	x.drain(t, s)
	if _, e := x.stop(context.Background(), s, x.client); e != nil {
		t.Fatal(e)
	}
	return x, s
}
func inspectCoreModel(ctx context.Context, x *stopTestModel, s *runtimeScope) (runtimeCoreInventory, error) {
	return s.inspectStoppedCoreWithProof(ctx, digest(encode(x.tx)), runtimeReq("b"), x.manager, x.proof.empty)
}

// Compare exact file bytes and path/inode/mode/mtime/size (not access time).
// No reader may remove a temp, repair a corrupt suffix, migrate or rewrite state.
func coreTree(t *testing.T, path string) map[string]string {
	t.Helper()
	out := map[string]string{}
	e := filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		var inode unix.Stat_t
		if e = unix.Lstat(p, &inode); e != nil {
			return e
		}
		value := fmt.Sprintf("%v/%v/%v/%v/%v", st.Mode(), st.Size(), st.ModTime().UnixNano(), inode.Dev, inode.Ino)
		if st.Mode().IsRegular() {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			value += fmt.Sprintf("/%x", sha256.Sum256(b))
		}
		if st.Mode()&os.ModeSymlink != 0 {
			v, e := os.Readlink(p)
			if e != nil {
				return e
			}
			value += "/" + v
		}
		out[strings.TrimPrefix(p, path)] = value
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}

func TestRuntimeCoreInventoryParsesExactOwnedAuthorityButNeverClaimsReclaim(t *testing.T) {
	x, s := stoppedCoreModel(t)
	seedCoreModel(t, x)
	before := coreTree(t, x.f.root.Name()+stateDir)
	if _, e := inspectCoreModel(context.Background(), x, s); e == nil {
		t.Fatal("no state lease accepted")
	}
	if e := ownStateModel(context.Background(), x, s); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 2; n++ {
		r, e := inspectCoreModel(context.Background(), x, s)
		if e != nil || !r.CoreAuthorityParsed || r.LedgerRecords != 1 || r.SessionRecords != 1 || r.LedgerNonterminal != 0 || r.SessionNonterminal != 0 || r.UnboundFailedTargets != 0 || r.AcceptedWorkComplete || r.ResourcesReclaimed || r.ActivationAllowed {
			t.Fatal(r, e)
		}
	}
	if _, e := s.inspectStoppedCore(context.Background(), digest(encode(x.tx)), runtimeReq("b"), x.manager); e == nil {
		t.Fatal("production accepted fake kernel domain")
	}
	if !reflect.DeepEqual(before, coreTree(t, x.f.root.Name()+stateDir)) {
		t.Fatal("inspection changed state")
	}
	if _, e := x.f.startupFilesLocked(context.Background()); e == nil {
		t.Fatal("inventory unfenced startup")
	}
	// The raw adapter owns its own OFD lease. Never recursively acquire it
	// under this scope, even in a negative test: that tests a self-deadlock,
	// not the maintenance-namespace refusal we actually intend to verify.
	s.close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := runtimeApply(ctx, x.f, x.tx, 0, runtimeReq("c"), "forward", nil); e != ErrInventory {
		t.Fatal("core parse authorized raw file selection")
	}
}

func TestRuntimeCoreInventoryClassifiesUnfinishedAndOrdinaryFailedTargetSemantics(t *testing.T) {
	for _, kind := range []string{"unfinished", "failed-target", "empty"} {
		t.Run(kind, func(t *testing.T) {
			x, s := stoppedCoreModel(t)
			r, j := seedCoreModel(t, x)
			switch kind {
			case "unfinished":
				r.State = sandbox.Reclaiming
				r.DestroyedAt = time.Time{}
				j.State = session.Active
				writeCoreModel(t, x, "ledger", r.ID, r)
				writeCoreModel(t, x, "sessions", j.ID, j)
			case "failed-target":
				j.Revision = 0
				j.Current = sandbox.Ref{}
				j.Attempts[0].State = "FAILED"
				j.Attempts[0].Target = sandbox.Ref{ID: runtimeReq("a"), Generation: runtimeReq("c")}
				j.Attempts[0].FencedAt = time.Time{}
				writeCoreModel(t, x, "sessions", j.ID, j)
			case "empty":
				for _, p := range []string{"ledger/" + r.ID + ".json", "sessions/" + j.ID + ".json"} {
					if e := os.Remove(x.f.root.Name() + stateDir + "/" + p); e != nil {
						t.Fatal(e)
					}
				}
			}
			if e := ownStateModel(context.Background(), x, s); e != nil {
				t.Fatal(e)
			}
			out, e := inspectCoreModel(context.Background(), x, s)
			if e != nil || !out.CoreAuthorityParsed || out.ResourcesReclaimed || out.AcceptedWorkComplete || out.ActivationAllowed {
				t.Fatal(out, e)
			}
			if kind == "unfinished" && (out.LedgerNonterminal != 1 || out.SessionNonterminal != 1) {
				t.Fatal(out)
			}
			if kind == "failed-target" && out.UnboundFailedTargets != 1 {
				t.Fatal(out)
			}
			if kind == "empty" && (out.LedgerRecords != 0 || out.SessionRecords != 0) {
				t.Fatal(out)
			}
		})
	}
}

func TestRuntimeCoreInventoryRefusesCorruptCrossAuthorityAndTempsWithoutRepair(t *testing.T) {
	for _, kind := range []string{"ledger-temp", "session-temp", "unknown-name", "symlink", "hardlink", "mode", "malformed", "unknown-field", "legacy", "oversize", "filename", "duplicate-ledger-key", "mock-backend", "orphan-target", "cross-tenant", "duplicate-session-key", "admission-drift", "identity-drift", "admission-temp", "admission-dir-mode", "missing-ledger"} {
		t.Run(kind, func(t *testing.T) {
			x, s := stoppedCoreModel(t)
			r, j := seedCoreModel(t, x)
			root := x.f.root.Name() + stateDir
			path := root + "/ledger/" + r.ID + ".json"
			check := func(e error) {
				if e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "ledger-temp":
				check(os.WriteFile(root+"/ledger/.record-123", []byte("partial"), 0600))
			case "session-temp":
				check(os.WriteFile(root+"/sessions/.session-123", []byte("partial"), 0600))
			case "unknown-name":
				check(os.WriteFile(root+"/ledger/foreign", []byte("foreign"), 0600))
			case "symlink":
				check(os.Rename(path, path+".original"))
				check(os.Symlink(path+".original", path))
			case "hardlink":
				check(os.Link(path, root+"/ledger/"+runtimeReq("9")+".json"))
			case "mode":
				check(os.Chmod(path, 0644))
			case "malformed":
				check(os.WriteFile(path, []byte("{"), 0600))
			case "unknown-field":
				b, e := os.ReadFile(path)
				check(e)
				check(os.WriteFile(path, bytes.Replace(b, []byte(`"version":1`), []byte(`"foreign":true,"version":1`), 1), 0600))
			case "legacy":
				b, e := json.Marshal(r)
				check(e)
				check(os.WriteFile(path, b, 0600))
			case "oversize":
				check(os.WriteFile(path, bytes.Repeat([]byte(" "), sandbox.MaxLedgerRecordBytes+1), 0600))
			case "filename":
				check(os.Rename(path, root+"/ledger/"+runtimeReq("9")+".json"))
			case "duplicate-ledger-key":
				r.ID = runtimeReq("9")
				writeCoreModel(t, x, "ledger", r.ID, r)
			case "mock-backend":
				r.Backend = "mock"
				writeCoreModel(t, x, "ledger", r.ID, r)
			case "orphan-target":
				j.Current.Generation = runtimeReq("9")
				j.Attempts[0].Target = j.Current
				writeCoreModel(t, x, "sessions", j.ID, j)
			case "cross-tenant":
				j.TenantID = "tenant-b"
				writeCoreModel(t, x, "sessions", j.ID, j)
			case "duplicate-session-key":
				j.ID = runtimeReq("9")
				writeCoreModel(t, x, "sessions", j.ID, j)
			case "admission-drift":
				d, e := x.f.runtimeDrainReadIntent()
				check(e)
				st := drainedRuntimeState(d)
				st.LastRequestID = runtimeReq("d")
				check(os.WriteFile(root+"/admission/state.json", encode(st), 0600))
			case "identity-drift":
				check(os.WriteFile(root+"/admission.identity", []byte(`{"version":1,"epoch":"`+runtimeReq("e")+`"}`), 0600))
			case "admission-dir-mode":
				check(os.Chmod(root+"/admission", 0755))
			case "admission-temp":
				check(os.WriteFile(root+"/admission/.state-123", []byte("partial"), 0600))
			case "missing-ledger":
				check(os.Rename(root+"/ledger", root+"/ledger.original"))
			}
			before := coreTree(t, root)
			if e := ownStateModel(context.Background(), x, s); e != nil {
				t.Fatal(e)
			}
			out, e := inspectCoreModel(context.Background(), x, s)
			if e == nil || out != (runtimeCoreInventory{}) {
				t.Fatal("partial inventory published", out, e)
			}
			if !reflect.DeepEqual(before, coreTree(t, root)) {
				t.Fatal("rejected state repaired")
			}
		})
	}
}

func TestRuntimeCoreInventoryCanceledAndBoundedReadersNeverRepair(t *testing.T) {
	x, s := stoppedCoreModel(t)
	seedCoreModel(t, x)
	if e := ownStateModel(context.Background(), x, s); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := inspectCoreModel(ctx, x, s); e != context.Canceled {
		t.Fatal(e)
	}
	stateFS := &filesystem{root: s.state.root}
	called := 0
	if e := scanCoreDirectory(context.Background(), stateFS, "/ledger", 0, sandbox.MaxLedgerRecordBytes, func(string, []byte) error { called++; return nil }); e == nil || called != 0 {
		t.Fatal("record bound ignored", e)
	}
	d, e := stateFS.directory("/ledger")
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if _, e = readCoreRecord(context.Background(), d, runtimeReq("1")+".json", 1); e == nil {
		t.Fatal("byte bound ignored")
	}
	// Current admission must still be the same exact drain, not reconstructed.
	b, e := stateFS.read("/admission/state.json", nodecontrol.StateLimit, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if len(b) == 0 {
		t.Fatal("admission removed")
	}
}
