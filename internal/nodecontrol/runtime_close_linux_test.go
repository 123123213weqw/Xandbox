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
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
)

func TestMaintenanceRuntimeClosePinnedActualBindingNotStatsAndClosedClientRefuses(t *testing.T) {
	x := runtimeCloseModel(t, nil, nil, nil, time.Second, time.Second)
	s, e := Start(x.root, x.c, func() sandbox.Stats { return sandbox.Stats{Active: 0} })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Stop()
	client, e := NewPinnedClient(x.root, os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	r, e := client.RuntimeClose(context.Background(), x.record, false)
	if e != nil || r.Phase != "idle" || r.Work.Frozen {
		t.Fatal(r, e)
	}
	if _, e = client.RuntimeClose(context.Background(), x.record, true); !errors.Is(e, ErrFenced) {
		t.Fatal("idle count bypassed completed-work barrier", e)
	}
	x.quiesce(t)
	if _, e = client.RuntimeClose(context.Background(), x.record, true); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r, e = client.RuntimeClose(context.Background(), x.record, false)
		if e != nil {
			t.Fatal(e)
		}
		if r.Phase == "closed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if r.Phase != "closed" || r.Core == nil || r.Core.Records != 1 || r.Sessions == nil || r.Sessions.Records != 1 {
		t.Fatal(r)
	}
	client.Close()
	if _, e = client.RuntimeClose(context.Background(), x.record, false); e == nil {
		t.Fatal("closed pin reused cached closure")
	}
}

func TestMaintenanceRuntimeClosePinnedStrictRepliesNeverAcceptPartialOrLegacyProof(t *testing.T) {
	record := MaintenanceRecord{Version: 1, Before: initialState(), Request: maintenanceRequest(initialState())}
	for _, kind := range []string{"valid", "idle-begin", "idle-status", "owner", "missing-core", "missing-sessions", "core-negative", "session-version", "not-frozen", "pending-work", "failed-work", "uncertain", "duplicate", "unknown", "trailing", "large", "legacy", "unsupported", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			copy := record
			r := RuntimeCloseReply{Version: 1, Maintenance: MaintenanceReply{Version: 1, Record: &copy, Control: Status{Version: 1, Committed: record.After(), Phase: "ready", DesiredMode: ModeDrained}}, Work: sandbox.AcceptedWorkStatus{Version: 1, Frozen: true}, Phase: "closed", Core: &sandbox.ClosureObservation{Version: 1, Records: 1, RecordsSHA256: strings.Repeat("a", 64)}, Sessions: &session.ClosureObservation{Version: 1, Records: 1, RecordsSHA256: strings.Repeat("b", 64)}}
			switch kind {
			case "idle-begin", "idle-status":
				r.Phase = "idle"
				r.Core = nil
				r.Sessions = nil
				r.Work.Frozen = false
			case "owner":
				copy.Request.Owner.OperationID = strings.Repeat("e", 32)
			case "missing-core":
				r.Core = nil
			case "missing-sessions":
				r.Sessions = nil
			case "core-negative":
				r.Core.Records = -1
			case "session-version":
				r.Sessions.Version = 2
			case "not-frozen":
				r.Work.Frozen = false
			case "pending-work":
				r.Work.Pending = 1
			case "failed-work":
				r.Work.Failed = 1
			case "uncertain":
				r.Work.Uncertain = true
			}
			data, _ := json.Marshal(r)
			switch kind {
			case "duplicate":
				data = append([]byte(`{"version":1,`), data[1:]...)
			case "unknown":
				data = append([]byte(`{"reclaimed":true,`), data[1:]...)
			case "trailing":
				data = append(data, data...)
			case "large":
				data = []byte(strings.Repeat("x", MaxReplyBytes+1))
			}
			var calls atomic.Int32
			root := pinnedServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if req.URL.Path != runtimeClosePath || req.Method != "POST" {
					t.Error("unexpected fallback", req.URL.Path)
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
			client, e := NewPinnedClient(root, os.Getpid())
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			_, e = client.RuntimeClose(context.Background(), record, kind != "idle-status")
			if (e == nil) != (kind == "valid" || kind == "idle-status") || calls.Load() != 1 {
				t.Fatal(kind, e, calls.Load())
			}
			if (kind == "legacy" || kind == "unsupported") && !errors.Is(e, ErrRuntimeCloseUnsupported) {
				t.Fatal(e)
			}
		})
	}
}
