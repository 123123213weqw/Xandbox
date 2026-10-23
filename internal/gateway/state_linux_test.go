//go:build linux

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayDurablePolicyCASColdReloadAndNoRollback(t *testing.T) {
	dir := t.TempDir()
	binding := strings.Repeat("a", 64)
	s, e := openPolicyState(dir, binding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := openPolicyState(dir, binding); e == nil {
		t.Fatal("second controller acquired policy lock")
	}
	snapshot, _ := testSnapshot(t)
	if e = s.Commit(snapshot); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = openPolicyState(dir, binding)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Commit(snapshot); e != nil {
		t.Fatal("exact restart changed policy")
	}
	next := snapshot
	next.Epoch = 2
	next.Keys = append([]ClientKey(nil), snapshot.Keys...)
	next.Keys[0].TokenSHA256 = tokenHash(strings.Repeat("d", 40))
	if e = s.Commit(next); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = openPolicyState(dir, binding)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Commit(next); e != nil {
		t.Fatal("new durable revision not recovered")
	}
	if s.Commit(snapshot) == nil {
		t.Fatal("old external key restored across restart")
	}
	changed := next
	changed.Keys = append([]ClientKey(nil), next.Keys...)
	changed.Keys[0].TokenSHA256 = tokenHash(strings.Repeat("e", 40))
	if s.Commit(changed) == nil {
		t.Fatal("same revision reused")
	}
	changed = next
	changed.Epoch = 4
	if s.Commit(changed) == nil {
		t.Fatal("skipped revision accepted")
	}
}
func TestGatewayPolicyStateMissingIdentityRecordAndUsedRootFailClosed(t *testing.T) {
	for _, remove := range []string{"policy.json", "policy.identity"} {
		dir := t.TempDir()
		s, e := openPolicyState(dir, strings.Repeat("a", 64))
		if e != nil {
			t.Fatal(e)
		}
		snapshot, _ := testSnapshot(t)
		if e = s.Commit(snapshot); e != nil {
			t.Fatal(e)
		}
		s.Close()
		os.Remove(filepath.Join(dir, remove))
		if _, e := openPolicyState(dir, strings.Repeat("a", 64)); e == nil {
			t.Fatal("lost authority auto-bootstrapped")
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "unknown"), []byte("x"), 0600)
	if _, e := openPolicyState(dir, strings.Repeat("a", 64)); e == nil {
		t.Fatal("used root opened as fresh")
	}
	dir = t.TempDir()
	s, e := openPolicyState(dir, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	snapshot, _ := testSnapshot(t)
	snapshot.Epoch = 2
	if s.Commit(snapshot) == nil {
		t.Fatal("fresh noninitial config accepted")
	}
	s.Close()
}
func TestGatewayStateBindingAndDirectoryCannotBeRetargeted(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	os.Mkdir(dir, 0700)
	s, e := openPolicyState(dir, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	snapshot, _ := testSnapshot(t)
	if e = s.Commit(snapshot); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if _, e := openPolicyState(dir, strings.Repeat("b", 64)); e == nil {
		t.Fatal("authority/socket binding retarget accepted")
	}
	s, e = openPolicyState(dir, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	os.Rename(dir, dir+"-old")
	os.Mkdir(dir, 0700)
	snapshot.Epoch = 2
	if s.Commit(snapshot) == nil {
		t.Fatal("private state directory swapped")
	}
}
