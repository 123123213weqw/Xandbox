//go:build linux

package firecracker

import (
	"errors"
	"strings"
	"testing"
	"unsafe"
)

func TestQuotaLinuxUAPIAndEnforcementParsers(t *testing.T) {
	if unsafe.Sizeof(projectAttr{}) != 28 || unsafe.Offsetof(projectAttr{}.ID) != 12 || unsafe.Sizeof(projectRecord{}) != 72 || unsafe.Offsetof(projectRecord{}.Valid) != 64 || unsafe.Sizeof(ext4UUID{}) != 24 || getExt4UUID != 0x8008662c {
		t.Fatal("wrong project/UUID UAPI")
	}
	if id, e := quotaMountID("pos:\t0\nmnt_id:\t81\n"); e != nil || id != "81" {
		t.Fatal("mount ID rejected", e)
	}
	for _, raw := range []string{"", "mnt_id: 0", "mnt_id: 081", "mnt_id: 1\nmnt_id: 2"} {
		if _, e := quotaMountID(raw); e == nil {
			t.Fatal("ambiguous mount ID accepted")
		}
	}
	good := "81 1 252:0 / /srv rw,nosuid - ext4 /dev/vda rw,prjquota"
	if e := quotaMountEnforced(good, "81", "252:0"); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{strings.Replace(good, "prjquota", "usrquota", 1), strings.Replace(good, "252:0", "252:1", 1), strings.Replace(good, "/srv rw,", "/srv ro,", 1), good + "\n" + good} {
		if e := quotaMountEnforced(raw, "81", "252:0"); e == nil {
			t.Fatal("wrong enforcement mount accepted")
		}
	}
	status := "CapEff: 0\nCapPrm: 0\nCapBnd: 0\nCapInh: 0\nCapAmb: 0\n"
	if e := quotaCapsAbsent(status); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"} {
		bad := strings.Replace(status, field+": 0", field+": 1000000", 1)
		if quotaCapsAbsent(bad) == nil {
			t.Fatal("resource capability bypass accepted")
		}
	}
	if quotaCapsAbsent("") == nil || quotaCapsAbsent(status+"CapEff: 0\n") == nil {
		t.Fatal("incomplete capability observation accepted")
	}
}
func fakeProjectQuota() (*projectQuota, map[uint32]projectRecord) {
	cfg := policy()
	cfg.Quota = quotaPolicy()
	data := map[uint32]projectRecord{}
	q := &projectQuota{cfg: cfg}
	q.get = func(id uint32) (projectRecord, error) { return data[id], nil }
	q.set = func(id uint32, r projectRecord) error { r.Valid = 0; data[id] = r; return nil }
	q.sync = func() error { return nil }
	return q, data
}
func TestQuotaRecoveryNeverAdoptsUnknownOrUnattemptedRecords(t *testing.T) {
	q, data := fakeProjectQuota()
	id := q.cfg.Quota.ProjectStart
	if e := q.reconcile(nil); e != nil {
		t.Fatal(e)
	}
	data[id] = q.limits()
	if e := q.reconcile(nil); e == nil {
		t.Fatal("unknown quota record adopted")
	}
	o := ownership{Version: 3, Ref: reference("1"), UID: q.cfg.UIDStart, ProjectID: id}
	owners := map[string]ownership{"owner": o}
	if e := q.reconcile(owners); e == nil {
		t.Fatal("unattempted owner adopted existing quota")
	}
	o.QuotaAttempted = true
	owners["owner"] = o
	if e := q.reconcile(owners); e != nil {
		t.Fatal("known attempted owner rejected", e)
	}
	bad := data[id]
	bad.Space = q.cfg.Quota.MaxBytes + 4096
	data[id] = bad
	if e := q.reconcile(owners); e == nil {
		t.Fatal("over-budget quota accepted")
	}
	data[id] = projectRecord{}
	if e := q.reconcile(owners); e != nil {
		t.Fatal("interrupted set or confirmed clear not recoverable", e)
	}
}
func TestQuotaAttemptIsDurableBeforeSetAndFailedPersistenceDoesNotTouchQuota(t *testing.T) {
	for _, fail := range []bool{false, true} {
		q, data := fakeProjectQuota()
		r, e := newRegistry(t.TempDir(), q.cfg, nil)
		if e != nil {
			t.Fatal(e)
		}
		o, e := r.reserve(reference("1"))
		if e != nil {
			t.Fatal(e)
		}
		k, _ := key(o.Ref)
		set := q.set
		called := false
		q.set = func(id uint32, v projectRecord) error {
			if !r.owners[k].QuotaAttempted {
				t.Fatal("quota syscall precedes durable attempt")
			}
			called = true
			return set(id, v)
		}
		if fail {
			r.persist = func(string, any) error { return errors.New("held/error fsync") }
		}
		e = q.reserveKnown(o, func() error { return r.markQuotaAttempt(k) })
		if fail {
			if e == nil || called || !emptyProject(data[o.ProjectID]) {
				t.Fatal("touched quota after failed ownership save")
			}
		} else if e != nil || !called {
			t.Fatal("new quota reservation failed", e)
		}
	}
}
func TestQuotaReleaseRetainsIdentityOnUsageDriftOrSyncError(t *testing.T) {
	q, data := fakeProjectQuota()
	o := ownership{Version: 3, Ref: reference("1"), UID: q.cfg.UIDStart, ProjectID: q.cfg.Quota.ProjectStart, QuotaAttempted: true}
	for _, mode := range []string{"space", "inode", "limits", "not-claimed", "sync"} {
		r := q.limits()
		owner := o
		switch mode {
		case "space":
			r.Space = 4096
		case "inode":
			r.Inodes = 1
		case "limits":
			r.BHard++
		case "not-claimed":
			owner.QuotaAttempted = false
		case "sync":
			q.sync = func() error { return errors.New("quota sync failed") }
		}
		data[o.ProjectID] = r
		if e := q.clearKnown(owner); e == nil {
			t.Fatal("unsafe quota release", mode)
		}
		if emptyProject(data[o.ProjectID]) {
			t.Fatal("limits cleared despite retained ownership", mode)
		}
		q.sync = func() error { return nil }
	}
	data[o.ProjectID] = q.limits()
	if e := q.clearKnown(o); e != nil || !emptyProject(data[o.ProjectID]) {
		t.Fatal("safe release rejected", e)
	}
}
