//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Exact pinned5f30 reader, including its original bounded file call and values
// returned on errors. Neither this reader nor its oracle authorizes effects.
func originalReadTransaction5f30(f *filesystem, name string) (transaction, error) {
	var t transaction
	raw, e := f.read(Root+"/"+name+".json", 65536, 0600)
	if e != nil {
		return t, e
	}
	if strictjson.Decode(raw, &t) != nil || !originalFileList5f30(t) || !bytes.Equal(raw, encode(t)) {
		return t, ErrInventory
	}
	return t, nil
}

func TestRuntimeFileTransactionRawReaderKeepsExactBoundsModesLinksAndInventory(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.MkdirAll(root+Root, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(root+Root+"/.lock", nil, 0600); e != nil {
				t.Fatal(e)
			}
			dir, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { dir.Close() })
			f := &filesystem{root: dir}
			seed := transactionValueSeed(version)
			invalid := cloneTransactionValue(seed)
			invalid.Version = 0
			if originalFileList5f30(invalid) {
				t.Fatal("invalid-policy guard control")
			}
			// Nil root would panic if either original entry-point guard were lost.
			emptyFS := &filesystem{}
			if !errors.Is(emptyFS.verifyTargets(context.Background(), invalid, true), ErrInventory) ||
				!errors.Is(emptyFS.verifyTargetsAgainst(context.Background(), invalid, true, nil), ErrInventory) {
				t.Fatal("unguarded verifier entry reached filesystem tail")
			}
			path := root + Root + "/commit.json"
			compare := func() (transaction, error) {
				t.Helper()
				want, old := originalReadTransaction5f30(f, "commit")
				got, err := f.readTransaction("commit")
				same := (old == nil) == (err == nil) && errors.Is(old, ErrInventory) == errors.Is(err, ErrInventory)
				if old != nil && !errors.Is(old, ErrInventory) {
					var a, b syscall.Errno
					same = same && errors.As(old, &a) && errors.As(err, &b) && a == b
				}
				if !same || !reflect.DeepEqual(want, got) {
					t.Fatal("original file IO/rejection/error-value behavior changed")
				}
				return got, err
			}
			for _, size := range []int{65535, 65536, 65537} {
				q := cloneTransactionValue(seed)
				q.Plan.Self.Path = "/bootstrap/"
				q.Plan.Self.Path += strings.Repeat("x", size-len(encode(q)))
				data := encode(q)
				if len(data) != size {
					t.Fatal("wrong outer file-ceiling control")
				}
				if e = os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
				got, err := compare()
				if err == nil || size > 65536 && !reflect.DeepEqual(got, transaction{}) {
					t.Fatal("oversized raw file decoded before original ceiling")
				}
			}
			for _, kind := range []string{"canonical", "no-LF", "unknown", "mode", "hardlink", "symlink", "directory", "missing", "scratch"} {
				t.Run(kind, func(t *testing.T) {
					for _, p := range []string{path, path + ".alias", root + Root + "/.commit.next"} {
						if e := os.Remove(p); e != nil && !errors.Is(e, os.ErrNotExist) {
							t.Fatal(e)
						}
					}
					data := encode(seed)
					if kind == "no-LF" {
						data = data[:len(data)-1]
					} else if kind == "unknown" {
						data = append([]byte(`{"unknown":1,`), data[1:]...)
					}
					if e := os.WriteFile(path, data, 0600); e != nil {
						t.Fatal(e)
					}
					var e error
					switch kind {
					case "mode":
						e = os.Chmod(path, 0644)
					case "hardlink":
						e = os.Link(path, path+".alias")
					case "symlink":
						e = os.Rename(path, path+".alias")
						if e == nil {
							e = os.Symlink("commit.json.alias", path)
						}
					case "directory":
						e = os.Remove(path)
						if e == nil {
							e = os.Mkdir(path, 0700)
						}
					case "missing":
						e = os.Remove(path)
					case "scratch":
						e = os.WriteFile(root+Root+"/.commit.next", []byte("partial"), 0600)
					}
					if e != nil {
						t.Fatal(e)
					}
					_, e = compare()
					accepted := kind == "canonical" || kind == "scratch"
					if (e == nil) != accepted {
						t.Fatal("reader accepted/refused outside original behavior", kind)
					}
					// A raw canonical value is not inventory authority. The ORIGINAL
					// committed-root guard still rejects the separate pending scratch.
					if kind == "scratch" && !errors.Is(f.rootInventory(version, true), ErrInventory) {
						t.Fatal("pending scratch lost original startup fence")
					}
				})
			}
		})
	}
}

// Existing TEST-only cut and manager model; no live service, kernel proof bypass
// or production callback. Only fixed stage labels change in the real loop.
func TestRuntimeStateClosePollStagesNameActualPreRPCPredicates(t *testing.T) {
	for _, kind := range []string{"input", "peers"} {
		t.Run(kind, func(t *testing.T) {
			x := stopModel(t, "")
			s := x.scope(t)
			x.maintain(t, s)
			hit := false
			x.f.hook = func(at string) error {
				if at == "runtime-close-before-begin" {
					hit = true
					if kind == "input" {
						return os.WriteFile(x.f.root.Name()+Root+"/auth.json", []byte("changed-test-source"), 0600)
					}
					x.alive[MainUnit] = false
				}
				return nil
			}
			ctx, cancel := workStopContext(t)
			defer cancel()
			proof, e := finishStopModel(ctx, x, s)
			wantCause := ErrInventory
			if kind == "peers" {
				wantCause = ErrConflict
			}
			if !hit || proof != nil || !errors.Is(e, wantCause) || !strings.HasPrefix(e.Error(), "runtime close poll-"+kind+":") || len(x.jobs) != 0 {
				t.Fatal("stale pre-RPC stage or rejected predicate reached Stop")
			}
			work := readWorkStopIntentTest(t, x.f)
			reply, e := x.client.RuntimeClose(context.Background(), *work.Drain.Maintenance, false)
			if e != nil || reply.Phase != "idle" || reply.Core != nil || reply.Sessions != nil {
				t.Fatal("rejected poll predicate reached irreversible close")
			}
			for _, name := range []string{runtimeCloseAnchor, runtimeStopRoot} {
				if yes, e := x.f.exists(name); e != nil || yes {
					t.Fatal("rejected poll predicate acquired terminal authority")
				}
			}
		})
	}
}
