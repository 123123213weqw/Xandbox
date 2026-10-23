package session

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

type nodeBoundDriver struct {
	sandbox.Driver
	seen []sandbox.AdmissionLimits
}

func (d *nodeBoundDriver) CheckAdmission(l sandbox.AdmissionLimits) error {
	d.seen = append(d.seen, l)
	if l.MaxSessions != 0 && l.MaxSessions != 2 || l.RetainedSessions > 2 {
		return errors.New("session count exceeds bound node envelope")
	}
	return nil
}

type nodeSessionStore struct {
	rows         []Record
	loads, saves int
}

func (s *nodeSessionStore) Load() ([]Record, error) { s.loads++; return s.rows, nil }
func (s *nodeSessionStore) Save(Record) error       { s.saves++; return nil }
func TestSessionMaximumAndRecoveredRowsRespectBackendEnvelope(t *testing.T) {
	base := t.TempDir()
	ledger, e := sandbox.NewFileStore(filepath.Join(base, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	mock, e := sandbox.NewMockDriver(filepath.Join(base, "runtime"))
	if e != nil {
		t.Fatal(e)
	}
	d := &nodeBoundDriver{Driver: mock}
	core, e := sandbox.NewManager(ledger, d, sandbox.Options{MaxInstances: 2})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if e := core.Close(ctx); e != nil {
			t.Error(e)
		}
	}()
	store := &nodeSessionStore{}
	if _, e = New(core, store, Options{}); e == nil || store.loads != 0 {
		t.Fatal("default session1000 bypassed envelope or loaded before check")
	}
	store.rows = make([]Record, 3)
	if _, e = New(core, store, Options{MaxSessions: 2}); e == nil || store.saves != 0 {
		t.Fatal("recovered session rows exceed envelope")
	}
	if d.seen[len(d.seen)-1].RetainedSessions != 3 {
		t.Fatal("recovered inventory was not checked")
	}
}
