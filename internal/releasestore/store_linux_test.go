//go:build linux

package releasestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var injected = errors.New("injected persistence boundary")

func fixture(t *testing.T) (*store, Manifest, func(context.Context, Manifest) ([]*os.File, error)) {
	t.Helper()
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	root, e := os.Open(base)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	s := &store{root: root}
	m := sampleManifest()
	source := t.TempDir()
	for i := range m.Files {
		v := &m.Files[i]
		v.Source = filepath.Join(source, v.Role)
		b := bytes.Repeat([]byte(v.Role+"-payload\n"), 8192)
		v.Bytes = int64(len(b))
		v.SHA256 = hash(b)
		if e := os.WriteFile(v.Source, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	input := func(ctx context.Context, m Manifest) ([]*os.File, error) {
		var f []*os.File
		for _, v := range m.Files {
			b, e := os.ReadFile(v.Source)
			if e != nil || int64(len(b)) != v.Bytes || hash(b) != v.SHA256 {
				for _, p := range f {
					p.Close()
				}
				return nil, ErrPolicy
			}
			p, e := os.Open(v.Source)
			if e != nil {
				return nil, e
			}
			f = append(f, p)
		}
		return f, nil
	}
	return s, m, input
}
func request() string { return strings.Repeat("a", 32) }
func TestPublicationAndExactRetryNoSource(t *testing.T) {
	s, m, open := fixture(t)
	r, e := s.publish(context.Background(), m, 0, request(), open)
	if e != nil || r.Revision != 1 || !r.PublicationDurable || r.ServicesChanged || r.ProductionReady {
		t.Fatal(r, e)
	}
	called := false
	gone := func(context.Context, Manifest) ([]*os.File, error) { called = true; return nil, ErrPolicy }
	r, e = s.publish(context.Background(), m, 0, request(), gone)
	if e != nil || r.Revision != 1 || called {
		t.Fatal("exact retry reread disappeared source or advanced", r, e)
	}
	v, e := s.status(context.Background())
	if e != nil || v != r {
		t.Fatal(v, e)
	}
	for _, change := range []func(*Manifest){func(m *Manifest) { m.SourceRevision = strings.Repeat("b", 40) }, func(m *Manifest) { m.Files[0].Source = "/different-private-source" }} {
		bad := m
		bad.Files = append([]File(nil), m.Files...)
		change(&bad)
		if _, e = s.publish(context.Background(), bad, 0, request(), gone); !errors.Is(e, ErrConflict) {
			t.Fatal("request identity rebound", e)
		}
	}
	if _, e = s.publish(context.Background(), m, 0, strings.Repeat("b", 32), open); !errors.Is(e, ErrConflict) {
		t.Fatal("stale CAS accepted", e)
	}
	next := m
	next.SourceRevision = strings.Repeat("b", 40)
	r, e = s.publish(context.Background(), next, 1, strings.Repeat("b", 32), open)
	if e != nil || r.Revision != 2 || r.Retained != 2 {
		t.Fatal(r, e)
	}
	next.SourceRevision = strings.Repeat("c", 40)
	if _, e = s.publish(context.Background(), next, 2, strings.Repeat("c", 32), open); !errors.Is(e, ErrCapacity) {
		t.Fatal("third retained bundle admitted", e)
	}
}
func TestEveryDurabilityBoundaryUnconfirmedThenExactRecovery(t *testing.T) {
	stages := []string{"intent-written", "intent-synced", "intent-renamed", "intent-durable", "bundle-manifest-written", "bundle-manifest-synced", "bundle-sealed", "bundle-renamed", "bundle-durable", "reference-written", "reference-synced", "reference-renamed", "reference-durable", "reference-committed", "intent-removed"}
	for _, r := range roles {
		for _, p := range []string{"written", "synced", "sealed"} {
			stages = append(stages, "artifact-"+p+"-"+r)
		}
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			s, m, open := fixture(t)
			hit := false
			s.hook = func(got string) error {
				if got == stage {
					hit = true
					return injected
				}
				return nil
			}
			if _, e := s.publish(context.Background(), m, 0, request(), open); !errors.Is(e, injected) || !hit {
				t.Fatal("boundary not exercised", e, hit)
			}
			s.hook = nil
			value, e := s.publish(context.Background(), m, 0, request(), open)
			if e != nil || value.Revision != 1 || !value.PublicationDurable {
				t.Fatal("same request recovery failed", value, e)
			}
			got, e := s.status(context.Background())
			if e != nil || got != value {
				t.Fatal("not durably closed", got, e)
			}
		})
	}
}
func TestPartialPrefixesOnlyAndUnknownInventory(t *testing.T) {
	for _, kind := range []string{"partial", "wrong-partial", "symlink", "hardlink", "unknown", "foreign-mode", "intent-scratch", "reference-scratch", "corrupt-sealed", "missing-retained"} {
		t.Run(kind, func(t *testing.T) {
			s, m, open := fixture(t)
			stage := "artifact-written-daemon"
			if kind == "intent-scratch" {
				stage = "intent-written"
			}
			if kind == "reference-scratch" {
				stage = "reference-written"
			}
			s.hook = func(got string) error {
				if got == stage {
					return injected
				}
				return nil
			}
			if _, e := s.publish(context.Background(), m, 0, request(), open); !errors.Is(e, injected) {
				t.Fatal(e)
			}
			s.hook = nil
			path := s.root.Name()
			file := filepath.Join(path, "pending", "daemon")
			source := m.Files[0].Source
			switch kind {
			case "partial":
				b, _ := os.ReadFile(source)
				if e := os.WriteFile(file, b[:37], 0600); e != nil {
					t.Fatal(e)
				}
			case "wrong-partial":
				if e := os.WriteFile(file, []byte("different-private-bytes"), 0600); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				os.Remove(file)
				if e := os.Symlink(source, file); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				os.Remove(file)
				if e := os.Link(source, file); e != nil {
					t.Fatal(e)
				}
			case "unknown":
				if e := os.WriteFile(filepath.Join(path, "pending", "foreign"), []byte("unknown"), 0600); e != nil {
					t.Fatal(e)
				}
			case "foreign-mode":
				if e := os.Chmod(file, 0644); e != nil {
					t.Fatal(e)
				}
			case "intent-scratch":
				if e := os.WriteFile(filepath.Join(path, ".intent.next"), []byte("unrelated"), 0600); e != nil {
					t.Fatal(e)
				}
			case "reference-scratch":
				if e := os.WriteFile(filepath.Join(path, ".ref.next"), []byte("unrelated"), 0600); e != nil {
					t.Fatal(e)
				}
			case "corrupt-sealed":
				if e := os.Chmod(file, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(file, []byte("corrupt"), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(file, 0500); e != nil {
					t.Fatal(e)
				}
			case "missing-retained": // First complete, then prove a reference alone cannot certify a lost bundle.
				if _, e := s.publish(context.Background(), m, 0, request(), open); e != nil {
					t.Fatal(e)
				}
				dir := filepath.Join(path, "objects", hash(description(m)))
				if e := os.Rename(dir, filepath.Join(path, "lost")); e != nil {
					t.Fatal(e)
				}
			}
			_, e := s.publish(context.Background(), m, 0, request(), open)
			if kind == "partial" {
				if e != nil {
					t.Fatal("matching partial not resumed", e)
				}
			} else if e == nil {
				t.Fatal("unknown/corrupt inventory accepted")
			}
		})
	}
}
func TestIncompleteStatusNoAutoResumeAndLaterCommitCleanup(t *testing.T) {
	s, m, open := fixture(t)
	s.hook = func(p string) error {
		if p == "reference-committed" {
			return injected
		}
		return nil
	}
	if _, e := s.publish(context.Background(), m, 0, request(), open); !errors.Is(e, injected) {
		t.Fatal(e)
	}
	s.hook = nil
	if _, e := s.status(context.Background()); !errors.Is(e, ErrConflict) {
		t.Fatal("status implicitly reconciled", e)
	}
	next := m
	next.SourceRevision = strings.Repeat("b", 40)
	if v, e := s.publish(context.Background(), next, 1, strings.Repeat("b", 32), open); e != nil || v.Revision != 2 {
		t.Fatal("post-commit intent did not reconcile", v, e)
	}
}
func TestCrossHandleLockCASAndCancellation(t *testing.T) {
	s, m, open := fixture(t)
	unlock, e := s.lock(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e = s.lock(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("lock not context-aware", e)
	}
	unlock()
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	conflict := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := fmt.Sprintf("%032x", i+1)
			_, e := s.publish(context.Background(), m, 0, req, open)
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				success++
			} else if errors.Is(e, ErrConflict) {
				conflict++
			} else {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	if success != 1 || conflict != 7 {
		t.Fatal(success, conflict)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, e = s.publish(ctx, m, 1, request(), open); !errors.Is(e, context.Canceled) {
		t.Fatal("canceled publication proceeded", e)
	}
}
func TestRootAPIsAndAnchoredFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		if _, e := Status(context.Background()); !errors.Is(e, ErrPlatform) {
			t.Fatal(e)
		}
		if _, e := Publish(context.Background(), "/secret-missing", 0, request()); !errors.Is(e, ErrPlatform) {
			t.Fatal(e)
		}
	}
	// Never traverse /tmp's writable ancestry, even when a private final file or
	// directory would otherwise pass owner/mode checks. No root mutation needed.
	if f, e := trusted("/tmp", true, false); e == nil {
		f.Close()
		t.Fatal("writable source ancestor trusted")
	}
	s, m, open := fixture(t)
	if _, e := s.publish(context.Background(), m, 0, request(), open); e != nil {
		t.Fatal(e)
	}
	lock := filepath.Join(s.root.Name(), ".lock")
	other := filepath.Join(t.TempDir(), "alias")
	if e := os.Link(lock, other); e != nil {
		t.Fatal(e)
	}
	if _, e := s.status(context.Background()); e == nil {
		t.Fatal("hard-linked lock admitted")
	}
}
func TestContextReaderAndPartialIntent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := io.ReadAll(contextReader{ctx, strings.NewReader("bytes")}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	s, m, open := fixture(t)
	s.hook = func(p string) error {
		if p == "intent-written" {
			return injected
		}
		return nil
	}
	if _, e := s.publish(context.Background(), m, 0, request(), open); !errors.Is(e, injected) {
		t.Fatal(e)
	}
	s.hook = nil
	p := filepath.Join(s.root.Name(), ".intent.next")
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, b[:17], 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.publish(context.Background(), m, 0, request(), open); e != nil {
		t.Fatal("matching intent prefix not recovered", e)
	}
}
func TestSealedBundleUnknownEntryAndPermissions(t *testing.T) {
	s, m, open := fixture(t)
	if _, e := s.publish(context.Background(), m, 0, request(), open); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(s.root.Name(), "objects", hash(description(m)))
	manifest, e := os.ReadFile(filepath.Join(root, "manifest.json"))
	if e != nil || bytes.Contains(manifest, []byte("/incoming")) {
		t.Fatal(e)
	}
	for _, v := range m.Files {
		info, e := os.Stat(filepath.Join(root, v.Role))
		if e != nil || uint32(info.Mode().Perm()) != fileMode(v.Role) {
			t.Fatal("not sealed", e)
		}
	}
	if e = os.WriteFile(filepath.Join(root, "foreign"), []byte("unknown"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.status(context.Background()); e == nil {
		t.Fatal("unknown bundle object admitted")
	}
}

func TestMatchingReferencePrefixAndUnboundScratchRefused(t *testing.T) {
	for _, kind := range []string{"matching-reference-prefix", "duplicate-intent-scratch", "unknown-root", "reference-noncanonical", "retained-mode", "same-key-different-manifest"} {
		t.Run(kind, func(t *testing.T) {
			s, m, open := fixture(t)
			stage := "reference-written"
			if kind == "duplicate-intent-scratch" {
				stage = "intent-renamed"
			}
			s.hook = func(got string) error {
				if got == stage {
					return injected
				}
				return nil
			}
			if _, e := s.publish(context.Background(), m, 0, request(), open); !errors.Is(e, injected) {
				t.Fatal(e)
			}
			s.hook = nil
			root := s.root.Name()
			switch kind {
			case "matching-reference-prefix":
				p := filepath.Join(root, ".ref.next")
				b, e := os.ReadFile(p)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(p, b[:13], 0600); e != nil {
					t.Fatal(e)
				}
			case "duplicate-intent-scratch":
				if e := os.WriteFile(filepath.Join(root, ".intent.next"), []byte("not this transaction"), 0600); e != nil {
					t.Fatal(e)
				}
			case "unknown-root":
				if e := os.WriteFile(filepath.Join(root, "foreign"), []byte("not owned"), 0600); e != nil {
					t.Fatal(e)
				}
			case "reference-noncanonical":
				if _, e := s.publish(context.Background(), m, 0, request(), open); e != nil {
					t.Fatal(e)
				}
				p := filepath.Join(root, "ref.json")
				b, e := os.ReadFile(p)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(p, append([]byte(" "), b...), 0600); e != nil {
					t.Fatal(e)
				}
			case "retained-mode":
				if e := os.Chmod(filepath.Join(root, "objects", hash(description(m)), "daemon"), 0700); e != nil {
					t.Fatal(e)
				}
			case "same-key-different-manifest":
				m.SourceRevision = strings.Repeat("c", 40)
			}
			_, e := s.publish(context.Background(), m, 0, request(), open)
			if kind == "matching-reference-prefix" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("unbound/unknown transaction accepted")
			}
		})
	}
}
