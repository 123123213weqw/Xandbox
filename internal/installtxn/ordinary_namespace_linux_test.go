//go:build linux

package installtxn

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/gateway"
	"golang.org/x/sys/unix"
)

// Literal paths independently enumerate ALL original startup vetoes plus
// unknown/future names that were not in its original closed list.
var ordinaryNamespaceCases = []struct{ label, path string }{
	{"files", "/etc/xandbox-runtime-files"}, {"drain", "/etc/xandbox-runtime-drain"},
	{"stop", "/etc/xandbox-runtime-stop"}, {"work", "/etc/xandbox-runtime-work"},
	{"work-anchor", "/etc/xandbox-runtime-work.identity"}, {"work-scratch", "/etc/.xandbox-runtime-work.identity.next"},
	{"close", "/etc/xandbox-runtime-close"}, {"close-anchor", "/etc/xandbox-runtime-close.identity"},
	{"close-scratch", "/etc/.xandbox-runtime-close.identity.next"}, {"results-close", "/etc/xandbox-runtime-results-close"},
	{"results-anchor", "/etc/xandbox-runtime-results-close.identity"}, {"results-scratch", "/etc/.xandbox-runtime-results-close.identity.next"},
	{"results-stop", "/etc/xandbox-runtime-results-stop"}, {"future", "/etc/xandbox-runtime-future-v99"},
	{"future-scratch", "/etc/.xandbox-runtime-future.next"}, {"bare-prefix", "/etc/xandbox-runtime"},
	{"raw-suffix", "/etc/xandbox-runtime-\xff"},
}

type ordinaryNamespaceEffects struct{ calls int }

func (m *ordinaryNamespaceEffects) fresh(context.Context) error     { m.calls++; return ErrPlatform }
func (m *ordinaryNamespaceEffects) reconcile(context.Context) error { m.calls++; return ErrPlatform }
func (m *ordinaryNamespaceEffects) current(context.Context) (bool, error) {
	m.calls++
	return false, ErrPlatform
}
func (m *ordinaryNamespaceEffects) reconcileManaged(context.Context) error {
	m.calls++
	return ErrPlatform
}
func (m *ordinaryNamespaceEffects) policy(context.Context, uint64, string, string, bool) (bool, error) {
	m.calls++
	return false, ErrPlatform
}
func (m *ordinaryNamespaceEffects) activateManaged(context.Context, uint64, string, string) (bool, error) {
	m.calls++
	return false, ErrPlatform
}
func (m *ordinaryNamespaceEffects) maintainIngress(context.Context, func() error) error {
	m.calls++
	return ErrPlatform
}

func ordinaryNamespaceInvoke(ctx context.Context, kind string, f *filesystem, m *ordinaryNamespaceEffects) error {
	req, prior := strings.Repeat("b", 32), strings.Repeat("c", 32)
	advance := func(gateway.Config, []byte, []byte, string) error { m.calls++; return ErrPlatform }
	var result Result
	var e error
	switch kind {
	case "install":
		result, e = installOperation(ctx, f, Plan{}, req, m, func(context.Context, Plan, bool) (*prepared, func(), error) {
			m.calls++
			return nil, nil, ErrPlatform
		})
	case "reconcile":
		result, e = reconcileOperationMaintenance(ctx, f, req, m, advance, advance)
	case "reconfigure":
		result, e = reconfigureOperation(ctx, f, RotationPlan{}, 1, req, m)
	case "recover":
		result, e = recoveryOperation(ctx, f, RotationPlan{}, 2, req, prior, m, advance)
	case "supersede":
		result, e = supersessionOperation(ctx, f, RotationPlan{}, 1, req, prior, m, advance, advance)
	case "discard":
		r, err := discardSupersessionDraftOperation(ctx, f, 1, req, strings.Repeat("a", 64), m, advance)
		if r != (DraftResult{}) {
			return errors.New("veto leaked a draft receipt")
		}
		return err
	default:
		panic("test entry selector")
	}
	if result != (Result{}) {
		return errors.New("veto leaked an installation receipt")
	}
	return e
}

func ordinaryNamespaceSnapshot(t *testing.T, f *filesystem) map[string]string {
	t.Helper()
	base := f.root.Name()
	out := map[string]string{}
	e := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			value += ":" + digest(raw)
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, e := os.Readlink(path)
			if e != nil {
				return e
			}
			value += ":" + target
		}
		out[strings.TrimPrefix(path, base)] = value
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}

func TestRuntimeFileOrdinaryNamespaceEveryProtectedEntryRefusesBeforeEffects(t *testing.T) {
	for _, ns := range ordinaryNamespaceCases {
		for _, entry := range []string{"install", "reconcile", "reconfigure", "recover", "supersede", "discard"} {
			t.Run(ns.label+"/"+entry, func(t *testing.T) {
				f := operationFixture(t) // Fresh minimal owned root, not a shared cached installation.
				if e := os.WriteFile(f.root.Name()+ns.path, []byte("unknown partial state"), 0600); e != nil {
					t.Fatal(e)
				}
				before := ordinaryNamespaceSnapshot(t, f)
				m := &ordinaryNamespaceEffects{}
				f.hook = func(stage string) error {
					if stage != "operation-lock-opened" && stage != "operation-lock-acquired" {
						m.calls++
					}
					return nil
				}
				e := ordinaryNamespaceInvoke(context.Background(), entry, f, m)
				f.hook = nil
				if !errors.Is(e, ErrInventory) || m.calls != 0 || !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, f)) {
					t.Fatal("ordinary entry crossed namespace veto or changed files", e, m.calls)
				}
				// Rejecting the wrapper must release ONLY its own operation FD.
				done, e := f.operationLock(context.Background(), true)
				if e != nil {
					t.Fatal("veto leaked original operation lease", e)
				}
				done()
			})
		}
	}
}

func TestRuntimeFileOrdinaryNamespaceEntryTypesNeverOpenedOrRepaired(t *testing.T) {
	for _, kind := range []string{"empty-directory", "partial-file", "dangling-symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			f := operationFixture(t)
			path := f.root.Name() + "/etc/xandbox-runtime-future"
			var e error
			switch kind {
			case "empty-directory":
				e = os.Mkdir(path, 0700)
			case "partial-file":
				e = os.WriteFile(path, []byte("{"), 0600)
			case "dangling-symlink":
				e = os.Symlink("absent-owned-target", path)
			case "fifo":
				e = unix.Mkfifo(path, 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			before := ordinaryNamespaceSnapshot(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e = f.runtimeNamespaceVeto(ctx); !errors.Is(e, ErrInventory) {
				t.Fatal("entry type bypassed veto", e)
			}
			// Neither reader may certify an unknown future prefix just because
			// it was absent from the old 13-path list. No fake commit is needed.
			if _, e = f.startupFilesLocked(ctx); !errors.Is(e, ErrInventory) {
				t.Fatal("startup ignored future prefix", e)
			}
			if _, e = f.inspectionBase(ctx, UpdateInspectionPlan{}); !errors.Is(e, ErrInventory) {
				t.Fatal("inspection ignored future prefix", e)
			}
			m := &ordinaryNamespaceEffects{}
			if r, err := f.status(ctx, m); !errors.Is(err, ErrInventory) || r != (Result{}) || m.calls != 0 {
				t.Fatal("status reported unknown runtime state or called manager", err)
			}
			if !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, f)) {
				t.Fatal("reader repaired/deleted/opened state")
			}
		})
	}
}

func TestRuntimeFileOrdinaryNamespaceFreshBootstrapAndLostLockStayUnchanged(t *testing.T) {
	for _, kind := range []string{"before-root", "before-original-lock", "lost-lock-with-contents", "absent-positive"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			if e := os.Mkdir(base+"/etc", 0700); e != nil {
				t.Fatal(e)
			}
			root, e := os.Open(base)
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			f := &filesystem{root: root}
			if kind != "before-root" {
				if e = os.Mkdir(base+Root, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "lost-lock-with-contents" {
				if e = os.WriteFile(base+Root+"/commit.json", []byte("retained unknown bytes"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if kind != "absent-positive" {
				if e = os.Mkdir(base+"/etc/xandbox-runtime-future", 0700); e != nil {
					t.Fatal(e)
				}
			}
			before := ordinaryNamespaceSnapshot(t, f)
			if kind == "before-root" {
				e = f.initialInstallRoot(context.Background())
			} else {
				var done func()
				done, e = f.ordinaryInitialOperationLock(context.Background())
				if done != nil {
					done()
				}
			}
			if kind != "absent-positive" {
				if !errors.Is(e, ErrInventory) || !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, f)) {
					t.Fatal("bootstrap created/repaired protected state", e)
				}
			} else {
				if e != nil {
					t.Fatal("empty fresh bootstrap refused", e)
				}
				a, e := os.Stat(base + Root + "/.lock")
				if e != nil || a.Size() != 0 {
					t.Fatal("original bootstrap lock", e)
				}
				done, e := f.ordinaryInitialOperationLock(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				done()
				b, e := os.Stat(base + Root + "/.lock")
				if e != nil || !os.SameFile(a, b) {
					t.Fatal("bootstrap replaced original inode", e)
				}
			}
		})
	}
}

func TestRuntimeFileOrdinaryNamespaceLeaseAndLateAppearance(t *testing.T) {
	for _, kind := range []string{"held-sh", "held-ex", "late-sh", "late-ex", "canceled-after-acquire"} {
		t.Run(kind, func(t *testing.T) {
			f := operationFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if strings.HasPrefix(kind, "late-") || kind == "canceled-after-acquire" {
				f.hook = func(stage string) error {
					if stage == "operation-lock-acquired" {
						if kind == "canceled-after-acquire" {
							cancel()
							return nil
						}
						return os.Mkdir(f.root.Name()+"/etc/xandbox-runtime-late", 0700)
					}
					return nil
				}
			}
			done, e := f.ordinaryOperationLock(ctx, strings.HasSuffix(kind, "-ex"))
			f.hook = nil
			if strings.HasPrefix(kind, "held-") {
				if e != nil {
					t.Fatal(e)
				}
				defer done()
				unrelated, err := f.open(Root+"/.lock", unix.O_RDONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				unrelated.Close()
				operationDenied(t, f, true)
				gate, err := f.startupReadLock(ctx)
				if err != nil {
					t.Fatal("operation veto introduced gate self-deadlock", err)
				}
				gate()
			} else {
				want := ErrInventory
				if kind == "canceled-after-acquire" {
					want = context.Canceled
				}
				if done != nil || !errors.Is(e, want) {
					t.Fatal("post-acquisition veto missing", e)
				}
				free, err := f.operationLock(context.Background(), true)
				if err != nil {
					t.Fatal("rejected original FD leaked", err)
				}
				free()
			}
		})
	}
}

func TestRuntimeFileOrdinaryNamespaceParentRefusalAndCancellation(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "regular", "writable", "pre-canceled", "closed-root"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			root, e := os.Open(base)
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			f := &filesystem{root: root}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "symlink":
				e = os.Mkdir(base+"/owned-target", 0700)
				if e == nil {
					e = os.Symlink("owned-target", base+"/etc")
				}
			case "regular":
				e = os.WriteFile(base+"/etc", []byte("owned"), 0600)
			case "writable":
				e = os.Mkdir(base+"/etc", 0700)
				if e == nil {
					e = os.Chmod(base+"/etc", 0777)
				}
			case "pre-canceled":
				cancel()
			case "closed-root":
				e = root.Close()
			}
			if e != nil {
				t.Fatal(e)
			}
			e = f.runtimeNamespaceVeto(ctx)
			if e == nil || kind == "pre-canceled" && !errors.Is(e, context.Canceled) {
				t.Fatal("uncertain parent became absence", e)
			}
		})
	}
}

func TestRuntimeFileOrdinaryNamespaceReservedByteLanguageAndBound(t *testing.T) {
	// Independent literal policy, not a call to the candidate prefix matcher.
	oracle := func(names []string) bool {
		if len(names) > 4096 {
			return false
		}
		for _, name := range names {
			if len(name) >= 15 && name[:15] == "xandbox-runtime" || len(name) >= 16 && name[:16] == ".xandbox-runtime" {
				return false
			}
		}
		return true
	}
	for _, tc := range []struct {
		name  string
		names []string
	}{
		{"empty", nil}, {"unrelated", []string{"xandbox-install", "xandbox-releases", "other"}},
		{"case-sensitive", []string{"Xandbox-runtime-future"}}, {"not-prefix", []string{"other-xandbox-runtime", "xandbox-runtim"}},
		{"reserved-stem", []string{"xandbox-runtime"}}, {"hidden-stem", []string{".xandbox-runtime"}},
		{"reserved-future", []string{"xandbox-runtime-v99"}}, {"hidden-future", []string{".xandbox-runtime-v99.next"}},
		{"exact-bound", make([]string, 4096)}, {"over-bound", make([]string, 4097)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (runtimeNamespaceNamesVeto(tc.names) == nil) != oracle(tc.names) {
				t.Fatal("literal prefix/bound policy differs")
			}
		})
	}
	for _, seed := range []string{"xandbox-runtime-future", ".xandbox-runtime-future.next"} {
		for _, pos := range []int{0, len(seed) / 2, len(seed) - 1} {
			for b := 0; b < 256; b++ {
				raw := []byte(seed)
				raw[pos] = byte(b)
				names := []string{string(raw)}
				if (runtimeNamespaceNamesVeto(names) == nil) != oracle(names) {
					t.Fatal("raw prefix policy differs", pos, b)
				}
			}
		}
	}
}

func TestRuntimeFileOrdinaryNamespaceOriginalRotationReallyMutated(t *testing.T) {
	for _, kind := range []string{"pinned-original", "guarded-current"} {
		t.Run(kind, func(t *testing.T) {
			f, _, p := rotationFixture(t, true)
			m := &rotationModelManager{managedModelManager: &managedModelManager{modelManager: &modelManager{}, active: true}}
			if e := os.WriteFile(f.root.Name()+"/etc/xandbox-runtime-future", []byte("unknown future bytes"), 0600); e != nil {
				t.Fatal(e)
			}
			before := ordinaryNamespaceSnapshot(t, f)
			var r Result
			var e error
			if kind == "pinned-original" {
				r, e = originalNamespaceReconfigure04(context.Background(), f, p, 1, strings.Repeat("b", 32), m)
			} else {
				r, e = reconfigureOperation(context.Background(), f, p, 1, strings.Repeat("b", 32), m)
			}
			after := ordinaryNamespaceSnapshot(t, f)
			if kind == "pinned-original" {
				if e != nil || r.Revision != 2 || !r.ManagerReconciled || m.activationCalls != 1 || reflect.DeepEqual(before, after) {
					t.Fatal("pre-change owned-model mutation was not reproduced", e)
				}
			} else if !errors.Is(e, ErrInventory) || r != (Result{}) || m.activationCalls != 0 || m.reconcileCalls != 0 || !reflect.DeepEqual(before, after) {
				t.Fatal("guarded real entry changed policy/model effects", e)
			}
		})
	}
}

func TestRuntimeFileOrdinaryNamespaceBoundedConcurrentReaders(t *testing.T) {
	f := operationFixture(t)
	before := ordinaryNamespaceSnapshot(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errorsOut := make(chan error, 4)
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 16; n++ {
				if e := f.runtimeNamespaceVeto(ctx); e != nil {
					errorsOut <- e
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errorsOut)
	for e := range errorsOut {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, f)) {
		t.Fatal("read-only concurrent veto changed owned root")
	}
	if e := os.WriteFile(f.root.Name()+"/etc/xandbox-runtime-new", []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := f.runtimeNamespaceVeto(ctx); !errors.Is(e, ErrInventory) {
		t.Fatal("absence cached across calls", e)
	}
}

// Verbatim pre-change04e entry below, with ONLY the function name changed.
// Its manager/artifacts are owned MODELS, never a real service/KVM certificate.
func originalNamespaceReconfigure04(ctx context.Context, f *filesystem, p RotationPlan, expected uint64, request string, manager serviceManager) (Result, error) {
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
