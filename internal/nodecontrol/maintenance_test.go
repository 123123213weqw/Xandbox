package nodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func maintenanceRequest(s State) MaintenanceRequest {
	return MaintenanceRequest{Version: 1, Owner: MaintenanceOwner{Version: 1, InstallCommitSHA256: strings.Repeat("a", 64), OperationID: strings.Repeat("c", 32)}, Command: command(s, "b")}
}
func maintenanceController(t *testing.T) (string, *FileStore, *Controller, *sandbox.AdmissionGate) {
	t.Helper()
	root := shortRoot(t)
	f, e := OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	gate := sandbox.NewAdmissionGate(true)
	c, e := New(f, gate)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	return root, f, c, gate
}

func TestMaintenanceDurableOwnerBlocksOrdinaryResumeAndExactRestartReplay(t *testing.T) {
	root, f, c, _ := maintenanceController(t)
	before := c.Status().Committed
	req := maintenanceRequest(before)
	r, e := c.BeginMaintenance(context.Background(), req)
	if e != nil || !r.valid() || r.Record == nil || r.Control.Committed != r.Record.After() || r.Control.AdmissionOpen {
		t.Fatal(r, e)
	}
	if r.Control.Committed.Revision != before.Revision+1 {
		t.Fatal(r)
	}
	for _, mode := range []string{ModeOpen, ModeDrained} {
		if _, e = c.Change(context.Background(), mode, command(r.Control.Committed, "d")); !errors.Is(e, ErrMaintenance) {
			t.Fatal("ordinary command bypassed held owner", e)
		}
	}
	for n := 0; n < 2; n++ {
		again, e := c.BeginMaintenance(context.Background(), req)
		if e != nil || again.Control != r.Control || *again.Record != *r.Record {
			t.Fatal("exact replay", again, e)
		}
	}
	wrong := req
	wrong.Owner.OperationID = strings.Repeat("d", 32)
	if _, e = c.BeginMaintenance(context.Background(), wrong); !errors.Is(e, ErrMaintenance) {
		t.Fatal(e)
	}
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	f, e = OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	gate := sandbox.NewAdmissionGate(true)
	next, e := New(f, gate)
	if e != nil || gate.Open() {
		t.Fatal("restart reopened", e)
	}
	defer next.Close(context.Background())
	if again, e := next.BeginMaintenance(context.Background(), req); e != nil || again.Control.Committed != r.Control.Committed || *again.Record != *r.Record {
		t.Fatal(again, e)
	}
	if _, e = next.Change(context.Background(), ModeOpen, command(r.Control.Committed, "e")); !errors.Is(e, ErrMaintenance) {
		t.Fatal(e)
	}
}

func TestMaintenancePreexistingDrainIsPreservedWithoutRevisionOrLastCommandRewrite(t *testing.T) {
	_, f, c, _ := maintenanceController(t)
	before := c.Status().Committed
	closed, e := c.Change(context.Background(), ModeDrained, command(before, "d"))
	if e != nil {
		t.Fatal(e)
	}
	before = closed.Committed
	req := maintenanceRequest(before)
	r, e := c.BeginMaintenance(context.Background(), req)
	if e != nil || r.Record == nil || r.Control.Committed != before || r.Record.After() != before {
		t.Fatal(r, e)
	}
	s, e := f.Load()
	if e != nil || s != before {
		t.Fatal("preexisting drain rewritten", s, e)
	}
}

var maintenanceCuts = []string{"maintenance-scratch-created", "maintenance-scratch-written", "maintenance-scratch-synced", "maintenance-fence-renamed", "maintenance-fence-dir-synced", "maintenance-fence-root-synced", "maintenance-before-identity", "maintenance-after-identity", "maintenance-before-state", "maintenance-after-state"}

func TestMaintenanceWriteAheadCutsKeepGateClosedAndExactLiveOwnerCanRecover(t *testing.T) {
	for _, cut := range maintenanceCuts {
		t.Run(cut, func(t *testing.T) {
			root, f, c, gate := maintenanceController(t)
			before := c.Status().Committed
			req := maintenanceRequest(before)
			hit := false
			f.maintenanceHook = func(at string) error {
				if at == cut {
					hit = true
					return errors.New("injected maintenance failure")
				}
				return nil
			}
			if _, e := c.BeginMaintenance(context.Background(), req); !errors.Is(e, ErrFenced) || !hit || gate.Open() || c.Status().Phase != "fenced" {
				t.Fatal("uncertain begin admitted work", e, hit, c.Status())
			}
			if _, e := c.Change(context.Background(), ModeOpen, command(before, "d")); !errors.Is(e, ErrMaintenance) {
				t.Fatal("resume bypassed uncertain lease", e)
			}
			if cut == "maintenance-scratch-created" {
				// An incomplete record cannot invent its owner after process death.
				if _, e := OpenStore(root); e == nil {
					t.Fatal("empty scratch opened startup")
				}
			}
			f.maintenanceHook = nil
			got, e := c.BeginMaintenance(context.Background(), req)
			if e != nil || got.Record == nil || got.Control.Committed != got.Record.After() || got.Control.Committed.Revision != before.Revision+1 || gate.Open() {
				t.Fatal("exact input recovery", got, e)
			}
			if e = c.Close(context.Background()); e != nil {
				t.Fatal(e)
			}
			nextStore, e := OpenStore(root)
			if e != nil {
				t.Fatal(e)
			}
			nextGate := sandbox.NewAdmissionGate(true)
			next, e := New(nextStore, nextGate)
			if e != nil || nextGate.Open() {
				t.Fatal("recovered startup reopened", e)
			}
			defer next.Close(context.Background())
			if next.Status().Committed != got.Control.Committed {
				t.Fatal("revision replayed twice")
			}
		})
	}
}

func TestMaintenanceUnknownPartialOrLostBindingNeverRepairsOrReopens(t *testing.T) {
	for _, kind := range []string{"wrong-owner", "bad-final", "bad-prefix", "duplicate-scratch", "missing-fence", "bad-anchor", "linked-fence", "symlink-fence", "public-fence", "missing-admission-identity", "foreign-state", "unknown-entry"} {
		t.Run(kind, func(t *testing.T) {
			root, _, c, _ := maintenanceController(t)
			req := maintenanceRequest(c.Status().Committed)
			reply, e := c.BeginMaintenance(context.Background(), req)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(root, "admission", MaintenanceName)
			b, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			check := func(e error) {
				if e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "wrong-owner":
				r := *reply.Record
				r.Request.Owner.OperationID = strings.Repeat("d", 32)
				check(os.WriteFile(path, maintenanceBytes(r), 0600))
			case "bad-final":
				check(os.WriteFile(path, []byte("{"), 0600))
			case "bad-prefix":
				check(os.Rename(path, filepath.Join(root, "admission", maintenanceScratch)))
				check(os.WriteFile(filepath.Join(root, "admission", maintenanceScratch), []byte("foreign"), 0600))
			case "duplicate-scratch":
				check(os.WriteFile(filepath.Join(root, "admission", maintenanceScratch), b, 0600))
			case "missing-fence":
				check(os.Remove(path))
			case "bad-anchor":
				check(os.WriteFile(filepath.Join(root, maintenanceIdentity), []byte(`{"version":1,"record_sha256":"`+strings.Repeat("d", 64)+`"}`), 0600))
			case "linked-fence":
				check(os.Link(path, filepath.Join(root, "alias")))
			case "symlink-fence":
				check(os.Rename(path, filepath.Join(root, "original")))
				check(os.Symlink(filepath.Join(root, "original"), path))
			case "public-fence":
				check(os.Chmod(path, 0644))
			case "missing-admission-identity":
				check(os.Remove(filepath.Join(root, "admission.identity")))
			case "foreign-state":
				s := reply.Control.Committed
				s.LastRequestID = strings.Repeat("e", 32)
				check(os.WriteFile(filepath.Join(root, "admission", "state.json"), []byte(marshalState(s)), 0600))
			case "unknown-entry":
				check(os.WriteFile(filepath.Join(root, "admission", "foreign"), []byte("foreign"), 0600))
			}
			before := maintenanceTree(t, root)
			if _, e := OpenStore(root); e == nil {
				t.Fatal("corruption admitted startup")
			}
			if !equalMaintenanceTree(before, maintenanceTree(t, root)) {
				t.Fatal("reader repaired corrupt authority")
			}
		})
	}
}
func marshalState(s State) string { b, _ := json.Marshal(s); return string(b) }

// Raw file bytes/modes/link targets only; no following symlinks or access-time
// assertion. Root remains a test-owned private tree, never a host installation.
func maintenanceTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		st, e := os.Lstat(path)
		if e != nil {
			return e
		}
		v := st.Mode().String()
		if st.Mode().IsRegular() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			v += "/" + string(b)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			s, e := os.Readlink(path)
			if e != nil {
				return e
			}
			v += "/" + s
		}
		out[strings.TrimPrefix(path, root)] = v
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func equalMaintenanceTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for n, v := range a {
		if b[n] != v {
			return false
		}
	}
	return true
}

func TestMaintenanceStoreCannotBeUsedAsOrdinaryResumeOrForeignOwnerWriter(t *testing.T) {
	_, f, c, _ := maintenanceController(t)
	before := c.Status().Committed
	req := maintenanceRequest(before)
	r, e := c.BeginMaintenance(context.Background(), req)
	if e != nil {
		t.Fatal(e)
	}
	next := r.Control.Committed
	next.Revision++
	next.LastExpectedRevision = next.Revision - 1
	next.LastRequestID = strings.Repeat("d", 32)
	next.Mode = ModeOpen
	if e = f.Save(r.Control.Committed, next); !errors.Is(e, ErrMaintenance) {
		t.Fatal("store bypassed fence", e)
	}
	copy := *r.Record
	copy.Request.Owner.OperationID = strings.Repeat("d", 32)
	if e = f.EnsureMaintenance(copy); e == nil {
		t.Fatal("foreign record replaced original")
	}
}

func TestMaintenanceSchemaCASUnsupportedAndMaxDrainedRevision(t *testing.T) {
	s := initialState()
	req := maintenanceRequest(s)
	r := MaintenanceRecord{Version: 1, Request: req, Before: s}
	if !r.Valid() {
		t.Fatal("valid schema refused")
	}
	for _, kind := range []string{"owner-version", "owner-base", "same-id", "before-epoch", "before-revision", "request-reuse"} {
		t.Run(kind, func(t *testing.T) {
			copy := r
			switch kind {
			case "owner-version":
				copy.Request.Owner.Version = 2
			case "owner-base":
				copy.Request.Owner.InstallCommitSHA256 = "bad"
			case "same-id":
				copy.Request.Owner.OperationID = copy.Request.Command.RequestID
			case "before-epoch":
				copy.Before.Epoch = strings.Repeat("d", 32)
			case "before-revision":
				copy.Before.Revision++
			case "request-reuse":
				copy.Before.Revision = 2
				copy.Before.LastRequestID = copy.Request.Command.RequestID
				copy.Before.LastExpectedRevision = 1
				copy.Request.Command.ExpectedRevision = 2
			}
			if copy.Valid() {
				t.Fatal("invalid maintenance record accepted")
			}
		})
	}
	s.Mode, s.Revision, s.LastExpectedRevision, s.LastRequestID = ModeDrained, math.MaxUint64, math.MaxUint64-1, strings.Repeat("e", 32)
	r = MaintenanceRecord{Version: 1, Before: s, Request: maintenanceRequest(s)}
	if !r.Valid() || r.After() != s {
		t.Fatal("terminal pre-drain revision changed")
	}
	c, e := New(&memoryStore{state: initialState()}, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.BeginMaintenance(context.Background(), req); !errors.Is(e, ErrMaintenanceUnsupported) || !c.Status().AdmissionOpen {
		t.Fatal("unsupported store mutated gate", e)
	}
}

func TestMaintenanceCanceledBeforeAcceptanceHasNoFilesystemEffects(t *testing.T) {
	root, _, c, _ := maintenanceController(t)
	before := maintenanceTree(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.BeginMaintenance(ctx, maintenanceRequest(c.Status().Committed)); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if !c.Status().AdmissionOpen || !equalMaintenanceTree(before, maintenanceTree(t, root)) {
		t.Fatal("unaccepted cancellation mutated authority")
	}
}

func TestMaintenancePendingIOKeepsStatusResponsiveAndAcceptedTicketUsable(t *testing.T) {
	root, f, c, gate := maintenanceController(t)
	ledger, e := sandbox.NewFileStore(filepath.Join(root, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	driver, e := sandbox.NewMockDriver(filepath.Join(root, "instances"))
	if e != nil {
		t.Fatal(e)
	}
	core, e := sandbox.NewManager(ledger, driver, sandbox.Options{AdmissionGate: gate, MaxInstances: 4})
	if e != nil {
		t.Fatal(e)
	}
	defer core.Close(context.Background())
	var ticket *sandbox.CreationTicket
	if e = core.ReserveSessionAttempt(func(v *sandbox.CreationTicket) { ticket = v }); e != nil {
		t.Fatal(e)
	}
	defer ticket.Release()
	before := c.Status().Committed
	entered, release := make(chan struct{}), make(chan struct{})
	f.maintenanceHook = func(at string) error {
		if at == "maintenance-scratch-created" {
			close(entered)
			<-release
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := c.BeginMaintenance(ctx, maintenanceRequest(before)); done <- e }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer not entered")
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	cancel() // Accepted cancellation does NOT release durable ownership.
	status := make(chan MaintenanceReply, 1)
	go func() { r, _ := c.MaintenanceStatus(); status <- r }()
	select {
	case r := <-status:
		if !r.valid() || r.Control.Phase != "pending" || r.Control.AdmissionOpen || r.Control.PendingSessionReservations != 1 {
			t.Fatal(r)
		}
	case <-time.After(time.Second):
		t.Fatal("status blocked behind disk")
	}
	if _, e = core.Create(context.Background(), sandbox.CreateRequest{}); !errors.Is(e, sandbox.ErrDraining) {
		t.Fatal(e)
	}
	if _, e = c.Change(context.Background(), ModeOpen, command(before, "d")); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	if _, e = c.BeginMaintenance(context.Background(), maintenanceRequest(before)); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	owner := sandbox.Owner{TenantID: "alpha", MaxInstances: 4}
	permit := sandbox.NewAdmission(func(sandbox.Ref) bool { return true })
	if _, e = core.CreateReservedManagedScoped(context.Background(), owner, "accepted", sandbox.CreateRequest{}, permit, func(sandbox.Ref) {}, ticket); e != nil || gate.Pending() != 0 {
		t.Fatal("accepted ticket canceled", e)
	}
	close(release)
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("writer did not complete")
	}
	if c.Status().AdmissionOpen || c.Status().Phase != "ready" {
		t.Fatal(c.Status())
	}
}

func TestMaintenanceCloseRetainsBlockedWriterAndNeverAcknowledgesLateSuccess(t *testing.T) {
	_, f, c, gate := maintenanceController(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.maintenanceHook = func(at string) error {
		if at == "maintenance-scratch-created" {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() {
		_, e := c.BeginMaintenance(context.Background(), maintenanceRequest(c.Status().Committed))
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer not entered")
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if e := c.Close(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if gate.Open() || c.Status().Phase != "closed" {
		t.Fatal("closing gate reopened")
	}
	close(release)
	select {
	case e := <-done:
		if !errors.Is(e, ErrClosed) {
			t.Fatal("late ACK", e)
		}
	case <-time.After(time.Second):
		t.Fatal("writer not reaped")
	}
	if e := c.Close(context.Background()); e != nil || gate.Open() {
		t.Fatal(e)
	}
}

func TestMaintenanceExactLiveOwnerCompletesOnlyItsOwnTruncatedPrefix(t *testing.T) {
	root, f, c, gate := maintenanceController(t)
	req := maintenanceRequest(c.Status().Committed)
	record := MaintenanceRecord{Version: 1, Request: req, Before: c.Status().Committed}
	f.maintenanceHook = func(at string) error {
		if at == "maintenance-scratch-created" {
			if e := os.WriteFile(filepath.Join(f.dir, maintenanceScratch), maintenanceBytes(record)[:17], 0600); e != nil {
				return e
			}
			return errors.New("partial owned write")
		}
		return nil
	}
	if _, e := c.BeginMaintenance(context.Background(), req); !errors.Is(e, ErrFenced) || gate.Open() {
		t.Fatal(e)
	}
	before := maintenanceTree(t, root)
	if _, e := OpenStore(root); e == nil || !equalMaintenanceTree(before, maintenanceTree(t, root)) {
		t.Fatal("unknown partial owner repaired")
	}
	other := req
	other.Owner.OperationID = strings.Repeat("e", 32)
	if _, e := c.BeginMaintenance(context.Background(), other); !errors.Is(e, ErrMaintenance) || !equalMaintenanceTree(before, maintenanceTree(t, root)) {
		t.Fatal("foreign owner changed prefix", e)
	}
	f.maintenanceHook = nil
	if r, e := c.BeginMaintenance(context.Background(), req); e != nil || r.Record == nil || *r.Record != record || gate.Open() {
		t.Fatal(r, e)
	}
}

// Models storage failing before it accepts ANY write, not a durability proof.
// The missing caller WAL/startup-fence integration must be visible, not hidden
// by testing only failures after a scratch already exists.
type prewriteMaintenanceStore struct{ *FileStore }

func (s *prewriteMaintenanceStore) EnsureMaintenance(MaintenanceRecord) error {
	return errors.New("no durable byte accepted")
}
func TestMaintenanceFailureBeforeAnyDurableByteRequiresExternalStartupFence(t *testing.T) {
	root, f, original, _ := maintenanceController(t)
	if e := original.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	gate := sandbox.NewAdmissionGate(false)
	c, e := New(&prewriteMaintenanceStore{f}, gate)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(context.Background())
	before := maintenanceTree(t, root)
	if _, e = c.BeginMaintenance(context.Background(), maintenanceRequest(c.Status().Committed)); !errors.Is(e, ErrFenced) || gate.Open() {
		t.Fatal(e)
	}
	if !equalMaintenanceTree(before, maintenanceTree(t, root)) {
		t.Fatal("prewrite model wrote bytes")
	}
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	nextStore, e := OpenStore(root)
	if e != nil {
		t.Fatal(e)
	}
	next, e := New(nextStore, sandbox.NewAdmissionGate(false))
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close(context.Background())
	if !next.Status().AdmissionOpen {
		t.Fatal("test premise: without durable caller WAL/fence the original open state remains")
	}
}
