package sandbox

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type boundedTestDriver struct {
	Driver
	calls  []AdmissionLimits
	reject func(AdmissionLimits) bool
}

func (d *boundedTestDriver) CheckAdmission(l AdmissionLimits) error {
	d.calls = append(d.calls, l)
	if d.reject != nil && d.reject(l) {
		return errors.New("bound envelope mismatch")
	}
	return nil
}
func TestResourceEnvelopeCheckedBeforeRecoveryWrites(t *testing.T) {
	base := t.TempDir()
	store, e := NewFileStore(filepath.Join(base, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	driver, e := NewMockDriver(filepath.Join(base, "runtime"))
	if e != nil {
		t.Fatal(e)
	}
	d := &boundedTestDriver{Driver: driver, reject: func(l AdmissionLimits) bool { return l.MaxInstances != 0 && l.MaxInstances != 2 }}
	if _, e = NewManager(store, d, Options{}); e == nil {
		t.Fatal("default32 bypassed backend node envelope")
	}
	if len(d.calls) != 1 || d.calls[0].MaxInstances != 32 || d.calls[0].MaxRecords != 10000 {
		t.Fatal("did not validate normalized defaults", d.calls)
	}
	d.reject = nil
	m, e := NewManager(store, d, Options{MaxInstances: 2})
	if e != nil {
		t.Fatal(e)
	}
	if e = m.CheckResourceAdmission(AdmissionLimits{MaxSessions: 16}); e != nil {
		t.Fatal(e)
	}
	if d.calls[len(d.calls)-1].MaxSessions != 16 {
		t.Fatal("session layer did not delegate to same backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = m.Close(ctx); e != nil {
		t.Fatal(e)
	}
}

type importAdmissionStore struct {
	rows  []Record
	saves int
}

func (s *importAdmissionStore) Load() ([]Record, error) { return s.rows, nil }
func (s *importAdmissionStore) Save(Record) error       { s.saves++; return nil }
func TestResourceEnvelopeImportedInventoryCannotSkipUnreclaimedStates(t *testing.T) {
	driver, e := NewMockDriver(filepath.Join(t.TempDir(), "runtime"))
	if e != nil {
		t.Fatal(e)
	}
	for _, state := range []State{Creating, Ready, Stopping, Stopped, Reclaiming} {
		store := &importAdmissionStore{rows: []Record{{State: state}, {State: Destroyed}}}
		d := &boundedTestDriver{Driver: driver, reject: func(l AdmissionLimits) bool { return l.AllocatedInstances > 0 }}
		if _, e = NewManager(store, d, Options{MaxInstances: 2}); e == nil {
			t.Fatal("recovery bypass", state)
		}
		if store.saves != 0 || len(d.calls) != 2 || d.calls[1].AllocatedInstances != 1 || d.calls[1].RetainedRecords != 2 {
			t.Fatal("import policy checked after writing a recovery fence", state, d.calls, store.saves)
		}
	}
}
