//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The synthetic native ELF headers below are PARSED AS DATA ONLY. They are not
// real runtime builds, source/ABI compatibility evidence or executable fixtures.
func runtimeStartupTargets(t *testing.T, p *prepared, version string) []target {
	t.Helper()
	art, e := descriptor(p.release)
	if e != nil {
		t.Fatal(e)
	}
	var out []target
	for _, v := range p.targets {
		if _, ok := runtimeFileModes()[v.file.Path]; !ok {
			continue
		}
		if v.file.Mode == 0555 {
			name := v.file.Path
			if name == childRoot+"/gateway" {
				name = rolePath("gateway")
			}
			v.data = append(elfFixture(), []byte("TEST DATA ONLY "+version+" "+name)...)
			v.source = nil
			v.file.SHA256, v.file.Bytes = digest(v.data), int64(len(v.data))
			for role, a := range art {
				if rolePath(role) == v.file.Path {
					a.SHA256, a.Bytes = v.file.SHA256, v.file.Bytes
					art[role] = a
				}
			}
		}
		out = append(out, v)
	}
	generated, e := render(p.plan, "1:1", art)
	if e != nil {
		t.Fatal(e)
	}
	for i, v := range out {
		if b, ok := generated[v.file.Path]; ok {
			out[i] = target{file: File{v.file.Path, digest(b), int64(len(b)), 0600}, data: b}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].file.Path < out[j].file.Path })
	return out
}
func runtimeStartupFixture(t *testing.T, managed bool) (*filesystem, transaction, []target) {
	t.Helper()
	makeFixture := fixture
	if managed {
		makeFixture = managedFixture
	}
	f, p, m := makeFixture(t)
	a := runtimeStartupTargets(t, p, "A")
	byPath := map[string]target{}
	for _, v := range a {
		byPath[v.file.Path] = v
	}
	for i, v := range p.targets {
		if next, ok := byPath[v.file.Path]; ok {
			p.targets[i] = next
		}
	}
	for i, v := range p.release.Files {
		if next, ok := byPath[rolePath(v.Role)]; ok {
			p.release.Files[i].SHA256, p.release.Files[i].Bytes = next.file.SHA256, next.file.Bytes
		}
	}
	p.plan.Self.SHA256 = byPath[SelfPath].file.SHA256
	p.plan.Release = digest(encode(p.release))
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	return f, tx, runtimeStartupTargets(t, p, "B")
}
func runtimeSelectStartup(t *testing.T, f *filesystem, tx transaction, targets []target) runtimeFileHead {
	t.Helper()
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); e != nil {
		t.Fatal(e)
	}
	h, e := f.runtimeSelectedFiles(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func runtimeShadowBytes(t *testing.T, f *filesystem) map[string]string {
	t.Helper()
	out := map[string]string{}
	e := filepath.WalkDir(f.root.Name(), func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, e := os.ReadFile(path)
		if e == nil {
			info, err := d.Info()
			if err != nil {
				return err
			}
			out[path] = digest(b) + ":" + info.Mode().String()
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}

func TestRuntimeStartupSelectedCompositionAndRollbackKeepGenesis(t *testing.T) {
	f, tx, targets := runtimeStartupFixture(t, false)
	before := runtimeProtectedBytes(t, f, tx)
	h := runtimeSelectStartup(t, f, tx, targets)
	if h.Revision != 1 || h.Base != digest(encode(tx)) {
		t.Fatal("overlay changed genesis")
	}
	// No OFD operation lock at this proof boundary: a maintenance owner may
	// hold EX while a future service gate takes only read-only SH flock.
	done, e := f.operationLock(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bytesBefore := runtimeShadowBytes(t, f)
	_, e = f.runtimeSelectedFiles(ctx)
	done()
	if e != nil || !bytes.Equal(encode(bytesBefore), encode(runtimeShadowBytes(t, f))) {
		t.Fatal("read proof mutated files or took maintenance lock", e)
	}
	if _, e = runtimeApply(ctx, f, tx, 1, runtimeReq("c"), "rollback", nil); e != nil {
		t.Fatal(e)
	}
	h, e = f.runtimeSelectedFiles(ctx)
	if e != nil || h.Revision != 2 || !bytes.Equal(encode(h.Current), encode(runtimeSubset(tx))) {
		t.Fatal("retained overlay", e)
	}
	unchangedRuntimeProtected(t, f, before)
	if _, e = f.startupFilesLocked(ctx); e == nil {
		t.Fatal("internal byte proof bypassed real startup fence")
	}
}

func TestRuntimeStartupManagedPolicyRemainsForwardAcrossFileRollback(t *testing.T) {
	f, tx, targets := runtimeStartupFixture(t, true)
	next := rotationSource(t, f, tx, "/bootstrap/runtime-startup-policy.json", 2)
	if _, e := rotateModel(context.Background(), f, tx, next, 1, runtimeReq("e"), func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	// Modeled ACK only, not actual frontend/systemd/PKI acceptance.
	if e := os.Remove(f.root.Name() + Root + "/rotation-intent.json"); e != nil {
		t.Fatal(e)
	}
	before := runtimeProtectedBytes(t, f, tx)
	runtimeSelectStartup(t, f, tx, targets)
	if _, e := runtimeApply(context.Background(), f, tx, 1, runtimeReq("c"), "rollback", nil); e != nil {
		t.Fatal(e)
	}
	if _, e := f.runtimeSelectedFiles(context.Background()); e != nil {
		t.Fatal(e)
	}
	_, policy, e := f.effectivePolicy(tx, true)
	if e != nil || policy.Revision != 2 || policy.Snapshot.Epoch != 2 {
		t.Fatal("runtime overlay rewound managed authority", e)
	}
	unchangedRuntimeProtected(t, f, before)
}

func TestRuntimeStartupRejectsHashConsistentInvalidCompositionAndPrograms(t *testing.T) {
	for _, kind := range []string{"generated-launch", "generated-ingress", "generated-ready", "main-unit", "ingress-unit", "gateway-copy", "script", "wrong-machine", "dynamic-self"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, targets := runtimeStartupFixture(t, false)
			path := map[string]string{"generated-launch": launchPath, "generated-ingress": ingressPath, "generated-ready": readyPath, "main-unit": UnitDir + "/" + MainUnit, "ingress-unit": UnitDir + "/" + IngressUnit, "gateway-copy": childRoot + "/gateway", "script": rolePath("daemon"), "wrong-machine": rolePath("node"), "dynamic-self": SelfPath}[kind]
			for i, v := range targets {
				if v.file.Path != path {
					continue
				}
				b := []byte("HASH CONSISTENT BUT NOT THE PRODUCTION RENDER\n")
				switch kind {
				case "gateway-copy":
					b = append(elfFixture(), []byte("DIFFERENT VALID GATEWAY COPY")...)
				case "script":
					b = []byte("#!/bin/sh\nexit 0\n")
				case "wrong-machine":
					b = elfFixture()
					b[18], b[19] = 0, 0
				case "dynamic-self":
					b = pieFixture()
				}
				targets[i] = target{file: File{path, digest(b), int64(len(b)), v.file.Mode}, data: b}
			}
			// The raw file engine intentionally does not certify semantics. A
			// coherent head/hash/retained-object set is insufficient for startup.
			if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); e != nil {
				t.Fatal(e)
			}
			before := runtimeShadowBytes(t, f)
			if _, e := f.runtimeSelectedFiles(context.Background()); e == nil {
				t.Fatal("accepted hash-consistent invalid selected composition")
			}
			if !bytes.Equal(encode(before), encode(runtimeShadowBytes(t, f))) {
				t.Fatal("verifier repaired or rewound files")
			}
		})
	}
}

func TestRuntimeStartupRejectsUncertainInventoryWithoutRepair(t *testing.T) {
	for _, kind := range []string{"fence-missing", "fence-stale", "fence-scratch", "intent", "head-scratch", "unknown-object", "retained-missing", "target-scratch", "unknown-asset", "backend-drift", "auth-drift", "genesis-drift", "side-mode", "child-mode"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, targets := runtimeStartupFixture(t, false)
			h := runtimeSelectStartup(t, f, tx, targets)
			path, b, mode := "", []byte("preserve uncertain bytes"), os.FileMode(0600)
			switch kind {
			case "fence-missing":
				if e := os.Remove(f.root.Name() + runtimeFilesFence); e != nil {
					t.Fatal(e)
				}
			case "retained-missing":
				current := map[string]bool{}
				for _, v := range h.Current {
					current[v.SHA256] = true
				}
				removed := false
				for _, v := range h.Previous {
					if !current[v.SHA256] {
						if e := os.Remove(f.root.Name() + runtimeFilesRoot + "/objects/" + v.SHA256); e != nil {
							t.Fatal(e)
						}
						removed = true
						break
					}
				}
				if !removed {
					t.Fatal("fixture lacks retained-only payload")
				}
			case "side-mode":
				if e := os.Chmod(f.root.Name()+runtimeFilesRoot, 0755); e != nil {
					t.Fatal(e)
				}
			case "child-mode":
				if e := os.Chmod(f.root.Name()+childRoot, 0700); e != nil {
					t.Fatal(e)
				}
			default:
				path = map[string]string{"fence-stale": runtimeFilesFence, "fence-scratch": Root + "/.runtime-files-pending.json.next", "intent": runtimeFilesRoot + "/intent.json", "head-scratch": runtimeFilesRoot + "/.head.json.next", "unknown-object": runtimeFilesRoot + "/objects/" + strings.Repeat("f", 64), "target-scratch": "/usr/libexec/.xandbox-launch.runtime-next", "unknown-asset": assetDir + "/foreign", "backend-drift": Root + "/backend.json", "auth-drift": Root + "/auth.json", "genesis-drift": Root + "/commit.json"}[kind]
			}
			if path != "" {
				if e := os.WriteFile(f.root.Name()+path, b, mode); e != nil {
					t.Fatal(e)
				}
			}
			before := runtimeShadowBytes(t, f)
			if _, e := f.runtimeSelectedFiles(context.Background()); e == nil {
				t.Fatal("uncertain inventory accepted")
			}
			if !bytes.Equal(encode(before), encode(runtimeShadowBytes(t, f))) {
				t.Fatal("uncertain bytes repaired/deleted")
			}
		})
	}
}

func TestRuntimeStartupLegacyGateCannotForgetSideJournalAfterRollback(t *testing.T) {
	f, tx, targets := runtimeStartupFixture(t, false)
	if _, e := f.startupFilesLocked(context.Background()); e != nil {
		t.Fatal("legacy baseline", e)
	}
	runtimeSelectStartup(t, f, tx, targets)
	if _, e := runtimeApply(context.Background(), f, tx, 1, runtimeReq("c"), "rollback", nil); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(f.root.Name() + runtimeFilesFence); e != nil {
		t.Fatal(e)
	}
	// The OLD immutable verifier accepts the genesis vector once the fence is
	// lost; the REAL gate's new journal-absence prerequisite must still refuse.
	if e := f.verifyTransaction(context.Background(), tx); e != nil {
		t.Fatal("negative-control premise", e)
	}
	if _, e := f.startupFilesLocked(context.Background()); e == nil {
		t.Fatal("lost fence authorized legacy startup")
	}
	// Even an empty surviving namespace is not permission to reset history.
	if e := os.RemoveAll(f.root.Name() + runtimeFilesRoot + "/objects"); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(f.root.Name() + runtimeFilesRoot + "/head.json"); e != nil {
		t.Fatal(e)
	}
	if _, e := f.startupFilesLocked(context.Background()); e == nil {
		t.Fatal("empty journal namespace allowed startup")
	}
}

func TestRuntimeStartupInputBindingIsDerivedNotJustDomainValid(t *testing.T) {
	f, tx, targets := runtimeStartupFixture(t, false)
	h := runtimeSelectStartup(t, f, tx, targets)
	for _, field := range []string{"input", "base", "request", "direction", "revision", "current"} {
		t.Run(field, func(t *testing.T) {
			bad := h
			bad.Current = append([]File(nil), h.Current...)
			switch field {
			case "input":
				bad.Input = strings.Repeat("f", 64)
			case "base":
				bad.Base = strings.Repeat("f", 64)
			case "request":
				bad.Request = runtimeReq("d")
			case "direction":
				bad.Direction = "rollback"
			case "revision":
				bad.Revision++
			case "current":
				bad.Current[0].SHA256 = strings.Repeat("f", 64)
			}
			if validRuntimeHead(bad, false) {
				t.Fatal("unrelated durable input accepted")
			}
			if e := os.WriteFile(f.root.Name()+runtimeFilesRoot+"/head.json", encode(bad), 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := f.runtimeHead(); e == nil {
				t.Fatal("canonical malformed authority decoded")
			}
			if e := os.WriteFile(f.root.Name()+runtimeFilesRoot+"/head.json", encode(h), 0600); e != nil {
				t.Fatal(e)
			}
		})
	}
	prior := h
	prior.Revision = ^uint64(0) - 1
	prior.Input = digest(encode(runtimeFileInput{Base: prior.Base, Expected: prior.Revision - 1, Request: prior.Request, Direction: prior.Direction, After: prior.Current}))
	intent := runtimeFileIntent{Version: 1, Prior: prior, Input: runtimeFileInput{Base: h.Base, Expected: prior.Revision, Request: runtimeReq("d"), Direction: "forward", After: h.Previous}}
	if validRuntimeIntent(intent) {
		t.Fatal("forward intent consumed reserved rollback revision")
	}
	intent.Input.Direction = "rollback"
	if !validRuntimeIntent(intent) || !validRuntimeHead(nextRuntimeHead(intent), false) {
		t.Fatal("reserved final rollback revision refused")
	}
}

func TestRuntimeStartupOriginalReadLockCancellationAndRebind(t *testing.T) {
	for _, kind := range []string{"missing", "nonempty", "rebound", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, targets := runtimeStartupFixture(t, false)
			runtimeSelectStartup(t, f, tx, targets)
			path := f.root.Name() + Root + "/.lock"
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			switch kind {
			case "missing":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
			case "nonempty":
				if e := os.WriteFile(path, []byte("not original"), 0600); e != nil {
					t.Fatal(e)
				}
			case "rebound":
				f.hook = func(at string) error {
					if at != "startup-lock-opened" {
						return nil
					}
					if e := os.Rename(path, path+".lost"); e != nil {
						return e
					}
					return os.WriteFile(path, nil, 0600)
				}
			case "cancel":
				unlock, e := f.existingLock(context.Background(), true)
				if e != nil {
					t.Fatal(e)
				}
				defer unlock()
			}
			_, e := f.runtimeSelectedFiles(ctx)
			if e == nil || kind == "cancel" && !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal("original lock prerequisite", e)
			}
			if kind == "missing" {
				if yes, _ := f.exists(Root + "/.lock"); yes {
					t.Fatal("lock recreated")
				}
			}
		})
	}
}

func TestRuntimeStartupRunningSelfUsesActualProcessNotGenesisPin(t *testing.T) {
	in, e := os.Open("/proc/self/exe")
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	st, e := in.Stat()
	if e != nil {
		t.Fatal(e)
	}
	sum, e := hashFile(context.Background(), in, st.Size())
	if e != nil {
		t.Fatal(e)
	}
	pin := File{SelfPath, sum, st.Size(), 0555}
	if e = runtimeRunningSelf(context.Background(), pin); e != nil {
		t.Fatal("actual test ELF self-byte match", e)
	}
	for _, kind := range []string{"genesis-hash", "size", "path", "mode", "digest"} {
		bad := pin
		switch kind {
		case "genesis-hash":
			bad.SHA256 = strings.Repeat("f", 64)
		case "size":
			bad.Bytes--
		case "path":
			bad.Path = "/another/executable"
		case "mode":
			bad.Mode = 0755
		case "digest":
			bad.SHA256 = "invalid"
		}
		if e = runtimeRunningSelf(context.Background(), bad); e == nil {
			t.Fatal("self pin bypass", kind)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = runtimeRunningSelf(ctx, pin); !errors.Is(e, context.Canceled) {
		t.Fatal("self hash ignored cancellation", e)
	}
}
