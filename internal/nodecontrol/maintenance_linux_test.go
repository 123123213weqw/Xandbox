//go:build linux

package nodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

// Actual test ELF + private files + ORIGINAL BSD state-lock primitive. There is
// no daemon, systemctl, backend, VM, unowned signal or quota operation here.
func TestMaintenanceCrashHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_MAINTENANCE_ROOT")
	if root == "" {
		return
	}
	lock, e := os.OpenFile(filepath.Join(root, "controller.lock"), os.O_RDWR|unix.O_NOFOLLOW, 0)
	if e != nil {
		os.Exit(71)
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		os.Exit(72)
	}
	f, e := OpenStore(root)
	if e != nil {
		os.Exit(73)
	}
	c, e := New(f, sandbox.NewAdmissionGate(false))
	if e != nil {
		os.Exit(74)
	}
	req := maintenanceRequest(c.Status().Committed)
	record := MaintenanceRecord{Version: 1, Request: req, Before: c.Status().Committed}
	cut := os.Getenv("XANDBOX_TEST_MAINTENANCE_CUT")
	f.maintenanceHook = func(at string) error {
		if cut == "maintenance-scratch-partial" && at == "maintenance-scratch-created" {
			if os.WriteFile(filepath.Join(f.dir, maintenanceScratch), maintenanceBytes(record)[:17], 0600) != nil {
				os.Exit(75)
			}
			at = cut
		}
		if at == cut {
			_ = unix.Kill(os.Getpid(), unix.SIGKILL)
			select {}
		}
		return nil
	}
	_, _ = c.BeginMaintenance(context.Background(), req)
	os.Exit(76) // Reaching here is failure: must have hit actual SIGKILL.
}

func TestMaintenanceActualSIGKILLFreshStateLockRecoveryOrUnknownPrefixRefusal(t *testing.T) {
	cuts := append(append([]string{}, maintenanceCuts...), "maintenance-scratch-partial")
	for _, cut := range cuts {
		t.Run(cut, func(t *testing.T) {
			root, _, c, _ := maintenanceController(t)
			before := c.Status().Committed
			req := maintenanceRequest(before)
			if e := c.Close(context.Background()); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(root, "controller.lock")
			lock, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if e != nil {
				t.Fatal(e)
			}
			lock.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMaintenanceCrashHelper$")
			child.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_MAINTENANCE_ROOT=" + root, "XANDBOX_TEST_MAINTENANCE_CUT=" + cut}
			out, e := child.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("own helper deadline", ctx.Err())
			}
			var exited *exec.ExitError
			if !errors.As(e, &exited) {
				t.Fatal("not an observed child death", e, string(out))
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || child.ProcessState == nil {
				t.Fatal("not actual reaped SIGKILL", e, string(out))
			}
			lock, e = os.OpenFile(path, os.O_RDWR|unix.O_NOFOLLOW, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer lock.Close()
			if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
				t.Fatal("dead writer retains original BSD lock", e)
			}
			snapshot := maintenanceTree(t, root)
			f, e := OpenStore(root)
			if cut == "maintenance-scratch-created" || cut == "maintenance-scratch-partial" {
				if e == nil || !equalMaintenanceTree(snapshot, maintenanceTree(t, root)) {
					t.Fatal("unknown owner guessed or repaired", e)
				}
				return
			}
			if e != nil {
				t.Fatal("complete record not recovered", e)
			}
			gate := sandbox.NewAdmissionGate(true)
			next, e := New(f, gate)
			if e != nil {
				t.Fatal(e)
			}
			defer next.Close(context.Background())
			r, e := next.BeginMaintenance(context.Background(), req)
			want := MaintenanceRecord{Version: 1, Request: req, Before: before}
			if e != nil || gate.Open() || r.Record == nil || *r.Record != want || r.Control.Committed != want.After() {
				t.Fatal("restart lost exact lease", r, e)
			}
			if _, e = next.Change(context.Background(), ModeOpen, command(r.Control.Committed, "d")); !errors.Is(e, ErrMaintenance) {
				t.Fatal("postcrash resume bypass", e)
			}
		})
	}
}

func TestMaintenancePinnedProcessRestartRetainsOwnerAndRejectsDeadPeer(t *testing.T) {
	root := shortRoot(t)
	child := pinnedChild(t, root)
	client, e := NewPinnedClient(root, child.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	before, e := client.Status(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	req := maintenanceRequest(before.Control.Committed)
	first, e := client.BeginMaintenance(context.Background(), before.Control.Committed, req)
	if e != nil || first.Record == nil {
		t.Fatal(e)
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e = child.Wait(); e == nil {
		t.Fatal("own helper death unobserved")
	}
	replacement := pinnedChild(t, root)
	if _, e = client.MaintenanceStatus(context.Background()); e == nil {
		t.Fatal("dead peer adopted replacement")
	}
	if _, e = client.BeginMaintenance(context.Background(), before.Control.Committed, req); e == nil {
		t.Fatal("dead peer ACK")
	}
	current, e := NewPinnedClient(root, replacement.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	r, e := current.MaintenanceStatus(context.Background())
	if e != nil || r.Record == nil || *r.Record != *first.Record || r.Control.AdmissionOpen {
		t.Fatal(r, e)
	}
	again, e := current.BeginMaintenance(context.Background(), before.Control.Committed, req)
	if e != nil || again.Control != r.Control || *again.Record != *r.Record {
		t.Fatal("retry rebound CAS", again, e)
	}
	legacy, e := NewClient(root)
	if e != nil {
		t.Fatal(e)
	}
	defer legacy.Close()
	if _, e = legacy.Change(context.Background(), ModeOpen, command(r.Control.Committed, "d")); e == nil || !strings.Contains(e.Error(), "HTTP409") {
		t.Fatal("legacy resume bypass", e)
	}
	current.Close()
	if _, e = current.BeginMaintenance(context.Background(), before.Control.Committed, req); e == nil {
		t.Fatal("closed client ACK")
	}
}

func TestMaintenancePinnedClientStrictReplyOwnershipAndLegacyRefusal(t *testing.T) {
	before := initialState()
	req := maintenanceRequest(before)
	record := MaintenanceRecord{Version: 1, Request: req, Before: before}
	for _, kind := range []string{"valid", "nil-record", "owner", "before", "after", "open", "pending", "pending-id", "version", "unknown", "duplicate", "trailing", "large", "legacy", "unsupported", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			copy := record
			reply := MaintenanceReply{Version: 1, Record: &copy, Control: Status{Version: 1, Committed: record.After(), Phase: "ready", DesiredMode: ModeDrained}}
			switch kind {
			case "nil-record":
				reply.Record = nil
			case "owner":
				copy.Request.Owner.OperationID = strings.Repeat("d", 32)
			case "before":
				copy.Before.Epoch = strings.Repeat("e", 32)
				copy.Request.Command.Epoch = copy.Before.Epoch
				reply.Control.Committed = copy.After()
			case "after":
				reply.Control.Committed.LastRequestID = strings.Repeat("e", 32)
			case "open":
				reply.Control.AdmissionOpen = true
			case "pending":
				reply.Control.Phase = "pending"
				reply.Control.PendingRequestID = req.Command.RequestID
			case "pending-id":
				reply.Control.Phase = "pending"
				reply.Control.PendingRequestID = strings.Repeat("e", 32)
			case "version":
				reply.Version = 2
			}
			payload, _ := json.Marshal(reply)
			switch kind {
			case "unknown":
				payload = append([]byte(`{"release":true,`), payload[1:]...)
			case "duplicate":
				payload = append([]byte(`{"version":1,`), payload[1:]...)
			case "trailing":
				payload = append(payload, payload...)
			case "large":
				payload = []byte(strings.Repeat("x", MaxReplyBytes+1))
			}
			var calls atomic.Int32
			root := pinnedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != maintenancePath || r.Method != "POST" {
					t.Error("unexpected fallback", r.URL.Path, r.Method)
				}
				switch kind {
				case "legacy":
					w.WriteHeader(404)
				case "unsupported":
					w.WriteHeader(501)
					payload = []byte(`{"code":"MAINTENANCE_UNSUPPORTED"}`)
				case "redirect":
					w.Header().Set("Location", "http://node.local/v1/node/drain")
					w.WriteHeader(307)
				}
				_, _ = w.Write(payload)
			}))
			c, e := NewPinnedClient(root, os.Getpid())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_, e = c.BeginMaintenance(context.Background(), before, req)
			if (e == nil) != (kind == "valid") {
				t.Fatal(kind, e)
			}
			if (kind == "legacy" || kind == "unsupported") && !errors.Is(e, ErrMaintenanceUnsupported) {
				t.Fatal(e)
			}
			if calls.Load() != 1 {
				t.Fatal("legacy fallback performed", calls.Load())
			}
		})
	}
}

func TestMaintenancePinnedClientClosedDuringReplyCannotAcknowledge(t *testing.T) {
	before := initialState()
	req := maintenanceRequest(before)
	record := MaintenanceRecord{Version: 1, Before: before, Request: req}
	entered, release := make(chan struct{}), make(chan struct{})
	root := pinnedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_ = json.NewEncoder(w).Encode(MaintenanceReply{Version: 1, Record: &record, Control: Status{Version: 1, Committed: record.After(), Phase: "ready", DesiredMode: ModeDrained}})
	}))
	c, e := NewPinnedClient(root, os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := c.BeginMaintenance(ctx, before, req); done <- e }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	c.Close()
	close(release)
	if e = <-done; e == nil {
		t.Fatal("closed pidfd lease ACK")
	}
}
