//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

func TestDiagnosticNoL0OrGenericRPC(t *testing.T) {
	n := &node{nodeBudget: true, quotaDriver: true}
	ctx := context.Background()
	for _, m := range []diagnosticHoldMode{diagnosticData, diagnosticHeader} {
		if _, e := n.diagnosticCheckpoint(ctx, m); e == nil {
			t.Fatal("L0 checkpoint")
		}
		if _, e := n.diagnosticRecover(ctx, m); e == nil {
			t.Fatal("L0 recovery")
		}
		for _, op := range []string{"node-diagnostics-checkpoint", "node-diagnostics-recover"} {
			q := nodeRequest{Version: 1, Operation: op, Phase: string(m)}
			if q.validate() != nil {
				t.Fatal("fixed operation")
			}
			q.Phase = "/arbitrary/path"
			if q.validate() == nil {
				t.Fatal("generic phase")
			}
			q.Phase = string(m)
			q.Receipt = []byte(`{}`)
			if q.validate() == nil {
				t.Fatal("generic receipt")
			}
		}
	}
	if _, e := n.startDiagnosticObserved(ctx); e == nil {
		t.Fatal("L0 launcher")
	}
	if e := diagnosticInputModes(nil, true); e == nil {
		t.Fatal("L0 input mutation")
	}
	if _, e := diagnosticAuthority(); e == nil {
		t.Fatal("L0 state scan")
	}
	if _, e := diagnosticRingDigest(); e == nil {
		t.Fatal("L0 ring scan")
	}
	if _, e := diagnosticMetrics(ctx); e == nil {
		t.Fatal("L0 metrics")
	}
	if diagnosticHoldMode("other").valid() || diagnosticData.observed() != 4 || diagnosticHeader.observed() != 5 || diagnosticHoldMax.Milliseconds() != 20000 || diagnosticProducers != 80 || diagnosticRecords != 82 {
		t.Fatal("fixed phase/resource contract")
	}
}
func testDiagnosticPrefix(n uint64) diagnostics.Snapshot {
	v := diagnostics.Snapshot{Version: 1, ObservedSequence: n, RetainedCapacity: 128}
	kinds := []diagnostics.Kind{diagnostics.ServiceKVM, diagnostics.ProcessStopped, diagnostics.CollectorClosed, diagnostics.ServiceKVM, diagnostics.PrepareFailed}
	for i := uint64(0); i < n; i++ {
		v.Records = append(v.Records, diagnostics.Record{Sequence: i + 1, Event: diagnostics.Event{Kind: kinds[i], TimeNS: int64(i + 1)}})
	}
	return v
}
func TestDiagnosticPrefixAndUnacknowledgedStageAreExact(t *testing.T) {
	for _, n := range []uint64{4, 5} {
		v := testDiagnosticPrefix(n)
		if diagnosticPrefix(v, n) != nil {
			t.Fatal("prefix")
		}
		v.Records[3].Event.Kind = diagnostics.ProcessFailed
		if diagnosticPrefix(v, n) == nil {
			t.Fatal("unrelated error")
		}
		v = testDiagnosticPrefix(n)
		v.Records[0].Event.DroppedBefore = 1
		if diagnosticPrefix(v, n) == nil {
			t.Fatal("lost prefix")
		}
	}
	if diagnosticPrefix(testDiagnosticPrefix(4), 5) == nil {
		t.Fatal("invented committed header")
	}
	data := make([]byte, diagnostics.RingBytes)
	offset := 2*128 + 5*128
	b := data[offset : offset+128]
	copy(b[:8], "XBDEVEN\x01")
	b[8] = 1
	b[9] = byte(diagnostics.PrepareFailed)
	binary.LittleEndian.PutUint64(b[16:24], 5)
	binary.LittleEndian.PutUint64(b[24:32], 1)
	crc := func() {
		binary.LittleEndian.PutUint32(b[124:], crc32.Checksum(b[:124], crc32.MakeTable(crc32.Castagnoli)))
	}
	crc()
	if e := diagnosticStage(data); e != nil {
		t.Fatal(e)
	}
	for _, index := range []int{0, 8, 9, 10, 11, 16, 32, 40, 124} {
		old := b[index]
		b[index] = 255
		if diagnosticStage(data) == nil {
			t.Fatal("bad CRC accepted")
		}
		if index != 124 {
			crc()
			if diagnosticStage(data) == nil {
				t.Fatal("bad stage semantics", index)
			}
		}
		b[index] = old
		crc()
	}
	if diagnosticStage(data[:len(data)-1]) == nil {
		t.Fatal("unbounded/truncated stage")
	}
}
func TestDiagnosticExactPressureWithoutPersistedAck(t *testing.T) {
	s := diagnostics.Stats{Enqueued: 66, Dropped: 15, Written: 1, Queued: 64, Capacity: 64, PrepareOther: diagnosticProducers}
	if diagnosticPressure(s) != nil {
		t.Fatal("pressure")
	}
	for i := 0; i < 9; i++ {
		b := s
		switch i {
		case 0:
			b.Enqueued++
		case 1:
			b.Dropped--
		case 2:
			b.Written++
		case 3:
			b.WriteErrors++
		case 4:
			b.Queued--
		case 5:
			b.Capacity++
		case 6:
			b.PrepareIO++
		case 7:
			b.PrepareQuota++
		case 8:
			b.PrepareOther--
		}
		if diagnosticPressure(b) == nil {
			t.Fatal("weakened pressure", i)
		}
	}
}
func goodDiagnosticSaved() diagnosticSaved {
	s := diagnosticSaved{Version: 1, Mode: diagnosticData, L1Boot: "11111111-1111-1111-1111-111111111111", RawBoot: "22222222-2222-2222-2222-222222222222", SessionBoot: "33333333-3333-3333-3333-333333333333", Config: strings.Repeat("a", 64), Authority: strings.Repeat("b", 64), Control: nodecontrol.State{Version: 1, Epoch: strings.Repeat("c", 32), Revision: 1, Mode: nodecontrol.ModeOpen}, Raw: sandbox.Ref{ID: strings.Repeat("d", 32), Generation: strings.Repeat("e", 32)}, Session: session.Result{ID: strings.Repeat("f", 32), Revision: 1, Current: sandbox.Ref{ID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}}, RawKey: strings.Repeat("3", 64), SessionKey: strings.Repeat("4", 64)}
	for i := 0; i < 80; i++ {
		s.FailedKeys = append(s.FailedKeys, fmt.Sprintf("%064x", i+10))
	}
	return s
}
func TestDiagnosticPrivateReceiptRejectsConfusion(t *testing.T) {
	s := goodDiagnosticSaved()
	boot := "44444444-4444-4444-4444-444444444444"
	if e := validateDiagnosticSaved(s, diagnosticData, boot); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 12; i++ {
		b := s
		b.FailedKeys = append([]string(nil), s.FailedKeys...)
		switch i {
		case 0:
			b.Mode = diagnosticHeader
		case 1:
			b.L1Boot = boot
		case 2:
			b.Config = "secret"
		case 3:
			b.Control.Revision = 2
		case 4:
			b.Control.Mode = nodecontrol.ModeDrained
		case 5:
			b.Raw = s.Session.Current
		case 6:
			b.Session.ID = "../arbitrary"
		case 7:
			b.SessionBoot = b.RawBoot
		case 8:
			b.FailedKeys[0] = b.RawKey
		case 9:
			b.FailedKeys = b.FailedKeys[:79]
		case 10:
			b.Authority = ""
		case 11:
			b.Session.Revision = 0
		}
		if validateDiagnosticSaved(b, diagnosticData, boot) == nil {
			t.Fatal("confused receipt", i)
		}
	}
}

// Regression for the first real d3 checkpoint failure: the already-CLOSED
// session has a legitimate final shutdown write BEFORE EXIT_GROUP entry. The
// refused contender must be compared to a snapshot AFTER that write.
func TestDiagnosticContenderBaselineMustFollowOrdinarySessionClose(t *testing.T) {
	root := t.TempDir()
	store, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	driver, e := sandbox.NewMockDriver(filepath.Join(root, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	manager, e := sandbox.NewManager(store, driver, sandbox.Options{MaxInstances: 2})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if e := manager.Close(ctx); e != nil {
			t.Error(e)
		}
	}()
	journal, e := session.NewFileStore(filepath.Join(root, "sessions"))
	if e != nil {
		t.Fatal(e)
	}
	broker, e := session.New(manager, journal, session.Options{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer broker.Close(ctx)
	first, e := broker.Open(ctx, sandbox.Owner{TenantID: "diagnostic-unit", MaxInstances: 2}, strings.Repeat("a", 64), sandbox.CreateRequest{})
	if e != nil {
		t.Fatal(e)
	}
	if e = broker.CloseSession("diagnostic-unit", first.ID, first.Revision); e != nil {
		t.Fatal(e)
	}
	// Load is a startup/recovery operation that may collect temp files. It must
	// never race the live journal writer, even in this private unit fixture.
	readNamed := func() (session.Record, error) {
		var env struct {
			Version int            `json:"version"`
			Record  session.Record `json:"record"`
		}
		data, e := privatefile.Read(filepath.Join(root, "sessions", first.ID+".json"), 16384)
		if e != nil {
			return env.Record, e
		}
		if e = strictjson.Decode(data, &env); e != nil {
			return env.Record, e
		}
		if env.Version != 1 || env.Record.ID != first.ID {
			return env.Record, fmt.Errorf("wrong named unit session")
		}
		return env.Record, nil
	}
	var before session.Record
	for {
		r, e := readNamed()
		if e == nil && r.State == session.Closed {
			before = r
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	if e = broker.Close(ctx); e != nil {
		t.Fatal(e)
	}
	after, e := readNamed()
	if e != nil {
		t.Fatal(e)
	}
	if !after.UpdatedAt.After(before.UpdatedAt) || after.State != session.Closed || after.Current != first.Current {
		t.Fatal("normal final closed-session write not observed")
	}
	after.UpdatedAt = before.UpdatedAt
	if !reflect.DeepEqual(after, before) {
		t.Fatal("unexpected session authority mutation beyond ordinary shutdown timestamp")
	}
}
