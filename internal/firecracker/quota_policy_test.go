package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func quotaPolicy() *QuotaPolicy {
	return &QuotaPolicy{Version: 1, FilesystemUUID: strings.Repeat("a", 32), ProjectStart: 1200000, MaxBytes: 192 << 20, MaxInodes: 128}
}
func TestQuotaPolicyIsBoundedCanonicalAndImmutable(t *testing.T) {
	c := policy()
	c.Quota = quotaPolicy()
	if e := c.validate(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Quota.Version = 0 }, func(c *Config) { c.Quota.FilesystemUUID = strings.Repeat("0", 32) }, func(c *Config) { c.Quota.FilesystemUUID = strings.Repeat("A", 32) },
		func(c *Config) { c.Quota.ProjectStart = 0 }, func(c *Config) { c.Quota.ProjectStart = ^uint32(0) }, func(c *Config) { c.Quota.MaxBytes++ }, func(c *Config) { c.Quota.MaxBytes = 1 },
		func(c *Config) { c.Quota.MaxInodes = 0 }, func(c *Config) { c.Quota.MaxInodes = 1 << 21 },
	} {
		bad := policy()
		bad.Quota = quotaPolicy()
		change(&bad)
		if bad.validate() == nil {
			t.Fatal("unsafe quota policy accepted")
		}
	}
	dir := t.TempDir()
	if _, e := newRegistry(dir, c, nil); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Config){func(c *Config) { c.Quota = nil }, func(c *Config) { c.Quota.ProjectStart++ }, func(c *Config) { c.Quota.MaxBytes += 4096 }, func(c *Config) { c.Quota.FilesystemUUID = strings.Repeat("b", 32) }} {
		bad := policy()
		bad.Quota = quotaPolicy()
		change(&bad)
		if _, e := newRegistry(dir, bad, nil); e == nil {
			t.Fatal("quota binding drift accepted")
		}
	}
	legacy := t.TempDir()
	old := policy()
	if _, e := newRegistry(legacy, old, nil); e != nil {
		t.Fatal(e)
	}
	old.Quota = quotaPolicy()
	if _, e := newRegistry(legacy, old, nil); e == nil {
		t.Fatal("quota silently enabled on old state")
	}
}
func TestQuotaOwnershipKeepsProjectAndUIDUntilQuotaAndDeletionProof(t *testing.T) {
	c := policy()
	c.Quota = quotaPolicy()
	r, e := newRegistry(t.TempDir(), c, nil)
	if e != nil {
		t.Fatal(e)
	}
	o, e := r.reserve(reference("1"))
	if e != nil || o.Version != 3 || o.ProjectID != c.Quota.ProjectStart || o.QuotaAttempted {
		t.Fatal("wrong initial quota ownership", o, e)
	}
	k, _ := key(o.Ref)
	if e = r.release(k); e == nil {
		t.Fatal("released without quota proof")
	}
	if _, e = os.Stat(filepath.Join(r.dir, k+".json")); e != nil {
		t.Fatal("owner lost before quota proof")
	}
	if e = r.markQuotaAttempt(k); e != nil {
		t.Fatal(e)
	}
	if e = r.markQuotaAttempt(k); e == nil {
		t.Fatal("quota attempt replayed")
	}
	r, e = newRegistry(r.dir, c, []sandbox.Record{ledger(o.Ref)})
	if e != nil || !r.owners[k].QuotaAttempted {
		t.Fatal("quota attempt lost after restart", e)
	}
	two, e := r.reserve(reference("2"))
	if e != nil || two.ProjectID == o.ProjectID {
		t.Fatal("live quota slot reused", e)
	}
	r.beforeRelease = func(owner ownership) error {
		if owner.ProjectID != o.ProjectID || !owner.QuotaAttempted {
			t.Fatal("wrong quota release identity")
		}
		return errors.New("quota I/O failure")
	}
	if e = r.release(k); e == nil {
		t.Fatal("ignored quota release failure")
	}
	if _, e = r.reserve(reference("3")); !errors.Is(e, sandbox.ErrCapacity) {
		t.Fatal("quota slot returned too soon", e)
	}
	r.beforeRelease = func(ownership) error { return nil }
	if e = r.release(k); e != nil {
		t.Fatal(e)
	}
	three, e := r.reserve(reference("3"))
	if e != nil || three.ProjectID != o.ProjectID || three.UID != o.UID {
		t.Fatal("durably reclaimed slot not reused", e)
	}
}
func TestQuotaOwnerVersionsAndInitializationCannotCrossPolicies(t *testing.T) {
	c := policy()
	c.Quota = quotaPolicy()
	r, e := newRegistry(t.TempDir(), c, nil)
	if e != nil {
		t.Fatal(e)
	}
	o, e := r.reserve(reference("1"))
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*ownership){func(o *ownership) { o.Version = 1 }, func(o *ownership) { o.ProjectID++ }, func(o *ownership) { o.ProjectID = 0 }, func(o *ownership) { o.TemplateID = strings.Repeat("a", 64) }, func(o *ownership) { o.InitializationAttempted = true }} {
		bad := o
		change(&bad)
		if validOwnership(bad, c) {
			t.Fatal("corrupt quota owner accepted")
		}
	}
	old := c
	old.Quota = nil
	if validOwnership(o, old) {
		t.Fatal("quota owner accepted under nil policy")
	}
	r, m, mem, st := catalogFixtureQuota(t, quotaPolicy())
	publishActive(t, r, m, mem, st)
	o, e = r.reserve(reference("2"))
	if e != nil || o.Version != 4 {
		t.Fatal("snapshot quota ownership missing", e)
	}
	k, _ := key(o.Ref)
	if e = r.markInitialization(context.Background(), k); e == nil {
		t.Fatal("initialized before durable quota attempt")
	}
	if e = r.markQuotaAttempt(k); e != nil {
		t.Fatal(e)
	}
	if e = r.markInitialization(context.Background(), k); e != nil {
		t.Fatal("version4 snapshot rejected", e)
	}
	if !r.owners[k].InitializationAttempted || !validOwnership(r.owners[k], r.cfg) {
		t.Fatal("snapshot quota epoch lost")
	}
}
