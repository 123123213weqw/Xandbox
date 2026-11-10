//go:build linux

package nodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestMaintenanceQuiescencePinnedChildDeathAndReplacementNeverReuseSuccess(t *testing.T) {
	root := shortRoot(t)
	child := pinnedChild(t, root)
	c, e := NewPinnedClient(root, child.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	before, e := c.Status(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	r, e := c.BeginMaintenance(context.Background(), before.Control.Committed, maintenanceRequest(before.Control.Committed))
	if e != nil {
		t.Fatal(e)
	}
	first, e := c.QuiesceMaintenance(context.Background(), *r.Record)
	if e != nil || !first.Work.Complete() {
		t.Fatal(first, e)
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e = child.Wait(); e == nil {
		t.Fatal("own death not observed")
	}
	replacement := pinnedChild(t, root)
	if _, e = c.QuiesceMaintenance(context.Background(), *r.Record); e == nil {
		t.Fatal("dead peer completion reused")
	}
	next, e := NewPinnedClient(root, replacement.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	after, e := next.QuiesceMaintenance(context.Background(), *r.Record)
	if e != nil || after.Work.Complete() || !after.Work.Uncertain || after.Work.Pending != 0 {
		t.Fatal("replacement guessed lost outcomes", after, e)
	}
}

func TestMaintenanceQuiescencePinnedClientStrictRecordAndStatus(t *testing.T) {
	record := MaintenanceRecord{Version: 1, Before: initialState(), Request: maintenanceRequest(initialState())}
	for _, kind := range []string{"valid", "foreign", "nil-record", "not-frozen", "uncertain", "failed", "negative", "version", "duplicate", "unknown", "trailing", "large", "legacy", "unsupported", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			copy := record
			r := MaintenanceWorkReply{Version: 1, Maintenance: MaintenanceReply{Version: 1, Record: &copy, Control: Status{Version: 1, Committed: record.After(), Phase: "ready", DesiredMode: ModeDrained}}, Work: sandbox.AcceptedWorkStatus{Version: 1, Frozen: true}}
			switch kind {
			case "foreign":
				copy.Request.Owner.OperationID = strings.Repeat("d", 32)
			case "nil-record":
				r.Maintenance.Record = nil
			case "not-frozen":
				r.Work.Frozen = false
			case "uncertain":
				r.Work.Uncertain = true
			case "failed":
				r.Work.Failed = 1
			case "negative":
				r.Work.Pending = -1
			case "version":
				r.Work.Version = 2
			}
			data, _ := json.Marshal(r)
			switch kind {
			case "duplicate":
				data = append([]byte(`{"version":1,`), data[1:]...)
			case "unknown":
				data = append([]byte(`{"force":true,`), data[1:]...)
			case "trailing":
				data = append(data, data...)
			case "large":
				data = []byte(strings.Repeat("x", MaxReplyBytes+1))
			}
			var calls atomic.Int32
			root := pinnedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != quiescencePath || r.Method != "POST" {
					t.Error("fallback", r.Method, r.URL.Path)
				}
				switch kind {
				case "legacy":
					w.WriteHeader(404)
				case "unsupported":
					w.WriteHeader(501)
				case "redirect":
					w.Header().Set("Location", "http://node.local/v1/node/drain")
					w.WriteHeader(307)
				}
				w.Write(data)
			}))
			c, e := NewPinnedClient(root, os.Getpid())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			got, e := c.QuiesceMaintenance(context.Background(), record)
			wantValid := kind == "valid" || kind == "uncertain" || kind == "failed"
			if (e == nil) != wantValid || calls.Load() != 1 {
				t.Fatal(kind, got, e, calls.Load())
			}
			if e == nil && got.Work.Complete() != (kind == "valid") {
				t.Fatal("invalid positive completion", got)
			}
			if (kind == "legacy" || kind == "unsupported") && !errors.Is(e, ErrMaintenanceUnsupported) {
				t.Fatal(e)
			}
		})
	}
}
