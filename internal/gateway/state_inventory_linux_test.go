//go:build linux

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func inventoryState(t *testing.T) (*policyState, Snapshot) {
	t.Helper()
	s, e := openPolicyState(t.TempDir(), strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	snapshot, _ := testSnapshot(t)
	if e = s.Commit(snapshot); e != nil {
		t.Fatal(e)
	}
	return s, snapshot
}
func inventoryWrite(t *testing.T, s *policyState, name string, v any, size int) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	b = append(b, '\n')
	if size > 0 {
		if len(b) > size {
			t.Fatal("test padding too small")
		}
		b = append(b, []byte(strings.Repeat(" ", size-len(b)))...)
	}
	if e = os.WriteFile(filepath.Join(s.dir, name), b, 0600); e != nil {
		t.Fatal(e)
	}
}
func inventoryOrphan(s *policyState) policyRecord {
	return policyRecord{Version: 1, Revision: s.record.Revision + 1, SnapshotSHA256: strings.Repeat("b", 64)}
}
func inventoryNamespace(t *testing.T, s *policyState) string {
	t.Helper()
	names, e := os.ReadDir(s.dir)
	if e != nil {
		t.Fatal(e)
	}
	out := []string{}
	for _, v := range names {
		p := filepath.Join(s.dir, v.Name())
		st, e := os.Lstat(p)
		if e != nil {
			t.Fatal(e)
		}
		value := ""
		if st.Mode()&os.ModeSymlink != 0 {
			value, e = os.Readlink(p)
		} else if st.Mode().IsRegular() {
			b, re := os.ReadFile(p)
			value = string(b)
			e = re
		}
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, fmt.Sprintf("%s/%v/%s", v.Name(), st.Mode(), digestJSON(value)))
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}
func TestGatewayInventoryRejectsUnknownAndUnsafeWithoutPartialCollection(t *testing.T) {
	cases := map[string]func(*testing.T, *policyState){
		"unknown":  func(t *testing.T, s *policyState) { inventoryWrite(t, s, "foreign", map[string]int{"x": 1}, 0) },
		"bad-name": func(t *testing.T, s *policyState) { inventoryWrite(t, s, ".policy-x", inventoryOrphan(s), 0) },
		"symlink": func(t *testing.T, s *policyState) {
			if e := os.Symlink("policy.json", filepath.Join(s.dir, ".policy-200")); e != nil {
				t.Fatal(e)
			}
		},
		"hardlink": func(t *testing.T, s *policyState) {
			if e := os.Link(filepath.Join(s.dir, ".policy-100"), filepath.Join(s.dir, ".policy-200")); e != nil {
				t.Fatal(e)
			}
		},
		"directory": func(t *testing.T, s *policyState) {
			if e := os.Mkdir(filepath.Join(s.dir, ".policy-200"), 0700); e != nil {
				t.Fatal(e)
			}
		},
		"partial": func(t *testing.T, s *policyState) {
			if e := os.WriteFile(filepath.Join(s.dir, ".policy-200"), []byte("{"), 0600); e != nil {
				t.Fatal(e)
			}
		},
		"unknown-field": func(t *testing.T, s *policyState) {
			inventoryWrite(t, s, ".policy-200", map[string]any{"version": 1, "revision": 2, "snapshot_sha256": strings.Repeat("b", 64), "extra": true}, 0)
		},
		"bad-version": func(t *testing.T, s *policyState) {
			v := inventoryOrphan(s)
			v.Version = 2
			inventoryWrite(t, s, ".policy-200", v, 0)
		},
		"future-revision": func(t *testing.T, s *policyState) {
			v := inventoryOrphan(s)
			v.Revision++
			inventoryWrite(t, s, ".policy-200", v, 0)
		},
		"zero-revision": func(t *testing.T, s *policyState) {
			v := inventoryOrphan(s)
			v.Revision = 0
			inventoryWrite(t, s, ".policy-200", v, 0)
		},
		"bad-digest": func(t *testing.T, s *policyState) {
			v := inventoryOrphan(s)
			v.SnapshotSHA256 = "bad"
			inventoryWrite(t, s, ".policy-200", v, 0)
		},
		"foreign-identity": func(t *testing.T, s *policyState) {
			inventoryWrite(t, s, ".identity-200", policyIdentity{Version: 1, BindingSHA256: strings.Repeat("c", 64)}, 0)
		},
		"oversize": func(t *testing.T, s *policyState) {
			inventoryWrite(t, s, ".policy-200", inventoryOrphan(s), policyMaxOrphanBytes+1)
		},
		"not-private": func(t *testing.T, s *policyState) {
			inventoryWrite(t, s, ".policy-200", inventoryOrphan(s), 0)
			if e := os.Chmod(filepath.Join(s.dir, ".policy-200"), 0640); e != nil {
				t.Fatal(e)
			}
		},
		"changed-authority": func(t *testing.T, s *policyState) { inventoryWrite(t, s, "policy.json", inventoryOrphan(s), 0) },
		"changed-identity": func(t *testing.T, s *policyState) {
			inventoryWrite(t, s, "policy.identity", policyIdentity{Version: 1, BindingSHA256: strings.Repeat("c", 64)}, 0)
		},
		"lock-data": func(t *testing.T, s *policyState) {
			if e := os.WriteFile(filepath.Join(s.dir, "gateway.lock"), []byte("x"), 0600); e != nil {
				t.Fatal(e)
			}
		},
		"lock-replaced": func(t *testing.T, s *policyState) {
			if e := os.Remove(filepath.Join(s.dir, "gateway.lock")); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(s.dir, "gateway.lock"), nil, 0600); e != nil {
				t.Fatal(e)
			}
		},
		"closed-root-fd": func(t *testing.T, s *policyState) {
			if e := s.root.Close(); e != nil {
				t.Fatal(e)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, snapshot := inventoryState(t)
			inventoryWrite(t, s, ".policy-100", inventoryOrphan(s), 0)
			mutate(t, s)
			before := inventoryNamespace(t, s)
			if s.Commit(snapshot) == nil {
				t.Fatal("unsafe inventory admitted")
			}
			if inventoryNamespace(t, s) != before {
				t.Fatal("failed inventory partially collected or rewrote authority")
			}
		})
	}
}
func TestGatewayInventoryBoundsAndExactReplayCollection(t *testing.T) {
	for _, over := range []bool{false, true} {
		t.Run(fmt.Sprint("entries-over=", over), func(t *testing.T) {
			s, snapshot := inventoryState(t)
			n := policyMaxOrphans
			if over {
				n++
			}
			for i := 0; i < n; i++ {
				inventoryWrite(t, s, fmt.Sprintf(".policy-%d", i), inventoryOrphan(s), 0)
			}
			before := inventoryNamespace(t, s)
			e := s.Commit(snapshot)
			if over {
				if e == nil || inventoryNamespace(t, s) != before {
					t.Fatal("overcount did not refuse unchanged")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			names, e := os.ReadDir(s.dir)
			if e != nil || len(names) != 3 {
				t.Fatal("known orphan inventory not fully collected")
			}
		})
	}
	for _, over := range []bool{false, true} {
		t.Run(fmt.Sprint("bytes-over=", over), func(t *testing.T) {
			s, snapshot := inventoryState(t)
			named := 0
			for _, name := range []string{"policy.json", "policy.identity", "gateway.lock"} {
				v, e := os.Stat(filepath.Join(s.dir, name))
				if e != nil {
					t.Fatal(e)
				}
				named += int(v.Size())
			}
			available := policyMaxBytes - named
			if over {
				available++
			}
			each := available / policyMaxOrphans
			for i := 0; i < policyMaxOrphans; i++ {
				n := each
				if i == policyMaxOrphans-1 {
					n = available - each*(policyMaxOrphans-1)
				}
				if n > policyMaxOrphanBytes {
					t.Fatal("test exceeds per-file bound instead of total")
				}
				inventoryWrite(t, s, fmt.Sprintf(".policy-%d", i), inventoryOrphan(s), n)
			}
			before := inventoryNamespace(t, s)
			e := s.Commit(snapshot)
			if over {
				if e == nil || inventoryNamespace(t, s) != before {
					t.Fatal("byte budget did not refuse unchanged")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestGatewayCollectionNeverBootstrapsFromOrphanAuthority(t *testing.T) {
	dir := t.TempDir()
	s, e := openPolicyState(dir, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	snapshot, _ := testSnapshot(t)
	inventoryWrite(t, s, ".policy-100", policyRecord{Version: 1, Revision: 1, SnapshotSHA256: digestJSON(snapshot)}, 0)
	before := inventoryNamespace(t, s)
	if s.Commit(snapshot) == nil || inventoryNamespace(t, s) != before {
		t.Fatal("orphan bootstrapped authority or changed unknown fresh root")
	}
}
func TestGatewayCollectionRejectsInvalidCASWithoutMutation(t *testing.T) {
	s, first := inventoryState(t)
	second := first
	second.Epoch = 2
	if e := s.Commit(second); e != nil {
		t.Fatal(e)
	}
	inventoryWrite(t, s, ".policy-100", inventoryOrphan(s), 0)
	before := inventoryNamespace(t, s)
	changed := second
	changed.ServerName = "different.example"
	for _, bad := range []Snapshot{first, changed} {
		if s.Commit(bad) == nil || inventoryNamespace(t, s) != before {
			t.Fatal("rejected CAS collected temporary metadata")
		}
	}
}
func TestGatewayTemporaryNamesHaveNoPathOrGeneralSelector(t *testing.T) {
	for _, name := range []string{".policy-1", ".identity-12345678901234567890"} {
		if _, ok := policyTemporary(name); !ok {
			t.Fatal("fixed temporary name rejected")
		}
	}
	for _, name := range []string{"policy.json", "../.policy-1", ".policy-", ".policy-1/other", ".policy-1\x00", ".policy-123456789012345678901", ".identity-x"} {
		if _, ok := policyTemporary(name); ok {
			t.Fatal("unbounded or foreign name accepted")
		}
	}
}
