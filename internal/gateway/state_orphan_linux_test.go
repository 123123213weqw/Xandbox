//go:build linux

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This regression intentionally uses only the pre-change state API so the
// identical test can execute against the original production implementation.
func TestGatewayCollectsOrphanOnlyAfterAuthorizedPolicyCAS(t *testing.T) {
	for _, advance := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact-replay", true: "next-revision"}[advance], func(t *testing.T) {
			dir := t.TempDir()
			s, e := openPolicyState(dir, strings.Repeat("a", 64))
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			first, _ := testSnapshot(t)
			if e = s.Commit(first); e != nil {
				t.Fatal(e)
			}
			next := first
			next.Epoch = 2
			orphan := policyRecord{Version: 1, Revision: 2, SnapshotSHA256: digestJSON(next)}
			b, e := json.Marshal(orphan)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, ".policy-123456789")
			if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
				t.Fatal(e)
			}
			bad := next
			bad.Epoch = 3
			if s.Commit(bad) == nil {
				t.Fatal("skipped revision accepted")
			}
			if got, e := os.ReadFile(path); e != nil || string(got) != string(append(b, '\n')) {
				t.Fatal("rejected CAS mutated orphan")
			}
			chosen := first
			if advance {
				chosen = next
			}
			if e = s.Commit(chosen); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Lstat(path); !os.IsNotExist(e) {
				t.Fatal("authorized commit retained orphan metadata")
			}
			s.Close()
			s, e = openPolicyState(dir, strings.Repeat("a", 64))
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if e = s.Commit(chosen); e != nil {
				t.Fatal("cold exact policy replay failed")
			}
		})
	}
}
