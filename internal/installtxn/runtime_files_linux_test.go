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

	"github.com/123123213weqw/Xandbox/internal/gateway"
)

func runtimeModel(t *testing.T) (*filesystem, transaction, []target) {
	t.Helper()
	f, p, m := fixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	return f, tx, runtimeModelTargets(p, "B")
}
func runtimeModelTargets(p *prepared, version string) []target {
	modes := runtimeFileModes()
	var out []target
	for _, v := range p.targets {
		if _, ok := modes[v.file.Path]; !ok {
			continue
		}
		v.data = append([]byte(nil), v.data...)
		if v.file.Path == rolePath("daemon") || v.file.Path == SelfPath || v.file.Path == Root+"/launch.json" {
			v.data = []byte("TEST ONLY " + version + " immutable image " + filepath.Base(v.file.Path))
			v.source = nil
			v.file.Bytes = int64(len(v.data))
			v.file.SHA256 = digest(v.data)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].file.Path < out[j].file.Path })
	return out
}
func runtimeReq(char string) string      { return strings.Repeat(char, 32) }
func stoppedModel(context.Context) error { return nil }
func runtimeApply(ctx context.Context, f *filesystem, tx transaction, expected uint64, req, direction string, targets []target) (runtimeFileResult, error) {
	return f.runtimeFileExchange(ctx, digest(encode(tx)), expected, req, direction, targets, stoppedModel)
}
func runtimeProtectedBytes(t *testing.T, f *filesystem, tx transaction) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	writable := runtimeFileModes()
	for _, v := range tx.Files {
		if _, ok := writable[v.Path]; ok {
			continue
		}
		b, e := os.ReadFile(f.root.Name() + v.Path)
		if e != nil {
			t.Fatal(e)
		}
		out[v.Path] = b
	}
	b, e := os.ReadFile(f.root.Name() + Root + "/commit.json")
	if e != nil {
		t.Fatal(e)
	}
	out[Root+"/commit.json"] = b
	return out
}
func unchangedRuntimeProtected(t *testing.T, f *filesystem, before map[string][]byte) {
	t.Helper()
	for path, raw := range before {
		b, e := os.ReadFile(f.root.Name() + path)
		if e != nil || !bytes.Equal(b, raw) {
			t.Fatal("protected authority changed", path, e)
		}
	}
}
func runtimeNoSources(in []target) []target {
	out := append([]target(nil), in...)
	for i := range out {
		out[i].data = nil
		out[i].source = nil
	}
	return out
}

func TestRuntimeFileForwardRollbackIsMonotonicAndNeverUnfencesStartup(t *testing.T) {
	f, tx, targets := runtimeModel(t)
	ctx := context.Background()
	before := runtimeProtectedBytes(t, f, tx)
	lock, _ := os.Stat(f.root.Name() + Root + "/.lock")
	// Model mutable authorities are outside the write allowlist and must not be
	// rewound even when the selected immutable images go back to the old version.
	for _, name := range []string{"ledger", "sessions", "owner", "catalog", "node"} {
		path := f.root.Name() + stateDir + "/" + name
		if e := os.WriteFile(path, []byte("forward-only "+name), 0600); e != nil {
			t.Fatal(e)
		}
		before[stateDir+"/"+name] = []byte("forward-only " + name)
	}
	r, e := runtimeApply(ctx, f, tx, 0, runtimeReq("b"), "forward", targets)
	if e != nil || r.Revision != 1 || !r.FilesSelected || !r.StartupBlocked || r.ActivationAllowed {
		t.Fatal(r, e)
	}
	if f.verifyTransaction(ctx, tx) == nil {
		t.Fatal("legacy startup accepted runtime fence")
	}
	h, e := f.runtimeHead()
	if e != nil || h.Revision != 1 {
		t.Fatal(h, e)
	}
	for _, v := range h.Current {
		if e = f.verify(ctx, v); e != nil {
			t.Fatal(e)
		}
	}
	// Lost-ACK retry needs metadata, not the original artifact producer.
	r, e = runtimeApply(ctx, f, tx, 0, runtimeReq("b"), "forward", runtimeNoSources(targets))
	if e != nil || r.Revision != 1 {
		t.Fatal(r, e)
	}
	r, e = runtimeApply(ctx, f, tx, 1, runtimeReq("c"), "rollback", nil)
	if e != nil || r.Revision != 2 || r.ActivationAllowed || !r.StartupBlocked {
		t.Fatal(r, e)
	}
	rolled, e := f.runtimeHead()
	if e != nil || !bytes.Equal(encode(rolled.Current), encode(runtimeSubset(tx))) {
		t.Fatal("not retained original images", e)
	}
	if f.verifyTransaction(ctx, tx) == nil {
		t.Fatal("binary rollback masqueraded as startup/health acceptance")
	}
	if _, e = runtimeApply(ctx, f, tx, 1, runtimeReq("c"), "rollback", nil); e != nil {
		t.Fatal("rollback lost ACK", e)
	}
	if _, e = runtimeApply(ctx, f, tx, 0, runtimeReq("d"), "forward", targets); !errors.Is(e, ErrConflict) {
		t.Fatal("stale CAS", e)
	}
	r, e = runtimeApply(ctx, f, tx, 2, runtimeReq("d"), "forward", runtimeNoSources(targets))
	if e != nil || r.Revision != 3 {
		t.Fatal(r, e)
	}
	unchangedRuntimeProtected(t, f, before)
	now, _ := os.Stat(f.root.Name() + Root + "/.lock")
	if !os.SameFile(lock, now) {
		t.Fatal("permanent installer lock replaced")
	}
}

func TestRuntimeFileRejectsMutablePathsInvalidBoundsAndUnprovenStop(t *testing.T) {
	for _, path := range []string{Root + "/commit.json", Root + "/auth.json", Root + "/backend.json", gateway.ManagedPolicyPath, stateDir + "/ledger", rolePath("kernel"), rolePath("warden"), "/arbitrary"} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, tx, targets := runtimeModel(t)
			targets = append([]target(nil), targets...)
			targets[0].file.Path = path
			if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); e == nil {
				t.Fatal("unqualified writable path")
			}
			if yes, _ := f.exists(runtimeFilesRoot); yes {
				t.Fatal("invalid request created transaction store")
			}
		})
	}
	f, tx, targets := runtimeModel(t)
	calls := 0
	stop := func(context.Context) error { calls++; return interrupted }
	if _, e := f.runtimeFileExchange(context.Background(), digest(encode(tx)), 0, runtimeReq("b"), "forward", targets, stop); !errors.Is(e, interrupted) || calls != 1 {
		t.Fatal("missing stopped prerequisite", e)
	}
	if yes, _ := f.exists(runtimeFilesRoot); yes {
		t.Fatal("unproven stop created store")
	}
	for _, n := range []uint64{^uint64(0), ^uint64(0) - 1} {
		if _, e := runtimeApply(context.Background(), f, tx, n, runtimeReq("b"), "forward", targets); e == nil {
			t.Fatal("overflow or no rollback runway")
		}
	}
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "rollback", nil); e == nil {
		t.Fatal("no retained version")
	}
	bad := append([]target(nil), targets...)
	bad[0].file.Bytes = 65 << 20
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", bad); e == nil {
		t.Fatal("unbounded artifact")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := runtimeApply(ctx, f, tx, 0, runtimeReq("b"), "forward", targets); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestRuntimeFileOriginalOperationLockExcludesMutationAndIsNotRecreated(t *testing.T) {
	f, tx, targets := runtimeModel(t)
	shared, e := f.operationLock(context.Background(), false)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, e = runtimeApply(ctx, f, tx, 0, runtimeReq("b"), "forward", targets)
	shared()
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("operation lock bypass", e)
	}
	if yes, _ := f.exists(runtimeFilesRoot); yes {
		t.Fatal("lock wait had effects")
	}
	if e = os.Remove(f.root.Name() + Root + "/.lock"); e != nil {
		t.Fatal(e)
	}
	if _, e = runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); e == nil {
		t.Fatal("missing permanent lock recreated")
	}
	if yes, _ := f.exists(Root + "/.lock"); yes {
		t.Fatal("permanent lock recreated")
	}
}

var runtimeCuts = []string{"runtime-intent-written", "runtime-intent-synced", "runtime-intent-renamed", "runtime-intent-durable", "runtime-old-objects-durable", "runtime-new-objects-durable", "runtime-startup-fence-written", "runtime-startup-fence-synced", "runtime-startup-fence-renamed", "runtime-startup-fence-durable", "runtime-swap-launch.json-renamed", "runtime-swap-launch.json-durable", "runtime-swap-sandboxd-renamed", "runtime-swap-sandboxd-durable", "runtime-swap-xandbox-install-renamed", "runtime-swap-xandbox-install-durable", "runtime-files-durable", "runtime-head-written", "runtime-head-synced", "runtime-head-renamed", "runtime-head-durable", "runtime-intent-unlinked", "runtime-intent-removed"}

func TestRuntimeFilePersistenceCutsFreshHandleRecoverSameRequest(t *testing.T) {
	for _, stage := range runtimeCuts {
		t.Run(stage, func(t *testing.T) {
			f, tx, targets := runtimeModel(t)
			before := runtimeProtectedBytes(t, f, tx)
			hit := false
			f.hook = func(at string) error {
				if at == stage && !hit {
					hit = true
					return interrupted
				}
				return nil
			}
			if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); !errors.Is(e, interrupted) || !hit {
				t.Fatal("cut not reached", stage, e)
			}
			root, e := os.Open(f.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			fresh := &filesystem{root: root}
			// The same request may finish a visible commit; it never decrements state
			// revision or interprets an interrupted file rename as health success.
			got, e := runtimeApply(context.Background(), fresh, tx, 0, runtimeReq("b"), "forward", targets)
			if e != nil || got.Revision != 1 || !got.StartupBlocked || got.ActivationAllowed {
				t.Fatal("fresh recovery", got, e)
			}
			if _, e = fresh.runtimeIntent(); e == nil {
				t.Fatal("intent not retired after durable file CAS")
			}
			unchangedRuntimeProtected(t, f, before)
		})
	}
}
func TestRuntimeFileAfterFirstSwapRecoveryDoesNotNeedProducer(t *testing.T) {
	f, tx, targets := runtimeModel(t)
	f.hook = func(at string) error {
		if at == "runtime-swap-sandboxd-renamed" {
			return interrupted
		}
		return nil
	}
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); !errors.Is(e, interrupted) {
		t.Fatal(e)
	}
	f.hook = nil
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("c"), "forward", targets); !errors.Is(e, ErrConflict) {
		t.Fatal("different request adopted intent", e)
	}
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", runtimeNoSources(targets)); e != nil {
		t.Fatal("lost producer after all objects durable", e)
	}
}
func TestRuntimeFileUnknownStateScratchOrObjectNeverAdopted(t *testing.T) {
	for _, kind := range []string{"unknown", "bad-head", "object", "fence-scratch", "canonical-scratch"} {
		t.Run(kind, func(t *testing.T) {
			f, tx, targets := runtimeModel(t)
			if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "unknown":
				os.WriteFile(f.root.Name()+runtimeFilesRoot+"/foreign", []byte("preserve"), 0600)
			case "bad-head":
				os.WriteFile(f.root.Name()+runtimeFilesRoot+"/head.json", []byte("{}\n"), 0600)
			case "object":
				os.WriteFile(f.root.Name()+runtimeFilesRoot+"/objects/"+strings.Repeat("f", 64), []byte("preserve"), 0400)
			case "fence-scratch":
				os.WriteFile(f.root.Name()+Root+"/.runtime-files-pending.json.next", []byte("preserve"), 0600)
			case "canonical-scratch":
				os.WriteFile(f.root.Name()+assetDir+"/.sandboxd.runtime-next", []byte("preserve"), 0600)
			}
			if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", runtimeNoSources(targets)); e == nil {
				t.Fatal("unknown state accepted")
			}
		})
	}
}
func TestRuntimeFileManagedPolicyBaseAndForwardKeysAreNeverRestored(t *testing.T) {
	f, p, m := managedFixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	// Construct a real forward policy envelope through the existing writer. The
	// fixture models its ACK removal; no frontend/systemd/PKI acceptance is claimed.
	next := rotationSource(t, f, tx, "/bootstrap/runtime-policy.json", 2)
	if _, e = rotateModel(context.Background(), f, tx, next, 1, runtimeReq("e"), func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(f.root.Name() + Root + "/rotation-intent.json"); e != nil {
		t.Fatal(e)
	}
	if e = f.syncDir(Root); e != nil {
		t.Fatal(e)
	}
	before := runtimeProtectedBytes(t, f, tx)
	targets := runtimeModelTargets(p, "B")
	if _, e = runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); e != nil {
		t.Fatal(e)
	}
	if _, e = runtimeApply(context.Background(), f, tx, 1, runtimeReq("c"), "rollback", nil); e != nil {
		t.Fatal(e)
	}
	unchangedRuntimeProtected(t, f, before)
	_, policy, e := f.effectivePolicy(tx, true)
	if e != nil || policy.Revision != 2 || policy.Snapshot.Epoch != 2 {
		t.Fatal("managed policy rewound or base changed", e)
	}
}
func TestRuntimeFileThirdVersionGCAndInterruptedReclaimStayBound(t *testing.T) {
	f, p, m := fixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	b, c := runtimeModelTargets(p, "B"), runtimeModelTargets(p, "C")
	if _, e = runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", b); e != nil {
		t.Fatal(e)
	}
	hit := false
	f.hook = func(at string) error {
		if at == "runtime-object-reclaimed" && !hit {
			hit = true
			return interrupted
		}
		return nil
	}
	if _, e = runtimeApply(context.Background(), f, tx, 1, runtimeReq("c"), "forward", c); !errors.Is(e, interrupted) || !hit {
		t.Fatal("reclaim cut", e)
	}
	f.hook = nil
	if _, e = runtimeApply(context.Background(), f, tx, 1, runtimeReq("c"), "forward", runtimeNoSources(c)); e != nil {
		t.Fatal(e)
	}
	if _, e = runtimeApply(context.Background(), f, tx, 2, runtimeReq("d"), "rollback", nil); e != nil {
		t.Fatal(e)
	}
	head, e := f.runtimeHead()
	if e != nil || head.Revision != 3 {
		t.Fatal(e)
	}
	for i, v := range head.Current {
		if v != b[i].file {
			t.Fatal("rollback not immediate retained version")
		}
	}
	if e = f.runtimeInventory(context.Background(), &head, nil); e != nil {
		t.Fatal("retained object inventory", e)
	}
}

func TestRuntimeFileNewRequestCannotAdoptUnrecognizedDesiredImages(t *testing.T) {
	f, p, m := fixture(t)
	tx, e := applyModel(context.Background(), f, p, request(), m)
	if e != nil {
		t.Fatal(e)
	}
	b, c := runtimeModelTargets(p, "B"), runtimeModelTargets(p, "C")
	if _, e = runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", b); e != nil {
		t.Fatal(e)
	}
	// The replacement is one of the next request's desired bytes, but no
	// matching intent ever authorized it. Never bless it as recovered work.
	for _, v := range c {
		if v.file.Path == rolePath("daemon") {
			path := f.root.Name() + v.file.Path
			if e = os.Chmod(path, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(path, v.data, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(path, 0555); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e = runtimeApply(context.Background(), f, tx, 1, runtimeReq("c"), "forward", c); e == nil {
		t.Fatal("adopted unrecognized desired replacement")
	}
	h, e := f.runtimeHead()
	if e != nil || h.Revision != 1 {
		t.Fatal("head changed despite drift", e)
	}
	if _, e = f.runtimeIntent(); e == nil {
		t.Fatal("new intent published despite drift")
	}
}

func TestRuntimeFileSecondStoppedObservationFailureLeavesNoTargetSwaps(t *testing.T) {
	f, tx, targets := runtimeModel(t)
	before := runtimeSubset(tx)
	calls := 0
	check := func(context.Context) error {
		calls++
		if calls == 2 {
			return interrupted
		}
		return nil
	}
	if _, e := f.runtimeFileExchange(context.Background(), digest(encode(tx)), 0, runtimeReq("b"), "forward", targets, check); !errors.Is(e, interrupted) {
		t.Fatal(e)
	}
	for _, v := range before {
		if e := f.verify(context.Background(), v); e != nil {
			t.Fatal("changed target without fresh stopped proof", e)
		}
	}
	if _, e := f.runtimeHead(); e == nil {
		t.Fatal("unqualified head committed")
	}
	if f.verifyTransaction(context.Background(), tx) == nil {
		t.Fatal("missing startup fence")
	}
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", runtimeNoSources(targets)); e != nil {
		t.Fatal("sealed producer-independent retry", e)
	}
}

func TestRuntimeFileMutableDriftMidSwapIsNotRestoredOrAcknowledged(t *testing.T) {
	f, tx, targets := runtimeModel(t)
	path := f.root.Name() + Root + "/auth.json"
	f.hook = func(at string) error {
		if at == "runtime-swap-sandboxd-renamed" {
			return os.WriteFile(path, []byte("forward external auth authority"), 0600)
		}
		return nil
	}
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); e == nil {
		t.Fatal("protected drift acknowledged")
	}
	if _, e := f.runtimeHead(); e == nil {
		t.Fatal("head committed after protected drift")
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != "forward external auth authority" {
		t.Fatal("restored an earlier auth snapshot", e)
	}
	if _, e := f.runtimeIntent(); e != nil {
		t.Fatal("lost uncertain intent", e)
	}
}

func TestRuntimeFileMissingRetainedObjectRefusesEvenLostAckRetry(t *testing.T) {
	f, tx, targets := runtimeModel(t)
	if _, e := runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", targets); e != nil {
		t.Fatal(e)
	}
	h, e := f.runtimeHead()
	if e != nil {
		t.Fatal(e)
	}
	for i, v := range h.Previous {
		if v.SHA256 != h.Current[i].SHA256 {
			if e = os.Remove(f.root.Name() + runtimeFilesRoot + "/objects/" + v.SHA256); e != nil {
				t.Fatal(e)
			}
			break
		}
	}
	if _, e = runtimeApply(context.Background(), f, tx, 0, runtimeReq("b"), "forward", runtimeNoSources(targets)); e == nil {
		t.Fatal("lost retained object silently accepted")
	}
}
