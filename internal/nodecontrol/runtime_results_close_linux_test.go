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

func TestRuntimeResultsPinnedActualSameProcessPeerAndClosedClientRefuses(t *testing.T) {
	x := runtimeResultsModel(t)
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
	if _, e = client.RuntimeClose(context.Background(), x.record, true); !errors.Is(e, ErrRuntimeCloseUnsupported) {
		t.Fatal(e)
	}
	r, e := client.RuntimeResultsClose(context.Background(), x.record, false)
	if e != nil || r.Phase != "idle" {
		t.Fatal(r, e)
	}
	x.quiesce(t)
	if _, e = client.RuntimeResultsClose(context.Background(), x.record, true); e != nil {
		t.Fatal(e)
	}
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		r, e = client.RuntimeResultsClose(context.Background(), x.record, false)
		if e != nil {
			t.Fatal(e)
		}
		if r.Phase == "closed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if r.Phase != "closed" || !r.valid() || r.Core.Results.Records != 1 {
		t.Fatal(r)
	}
	client.Close()
	if _, e = client.RuntimeResultsClose(context.Background(), x.record, false); e == nil {
		t.Fatal("closed pin reused cache")
	}
}
func TestRuntimeResultsPinnedStrictRepliesNeverAdoptPartialOrRecordOnlyAuthority(t *testing.T) {
	record := MaintenanceRecord{Version: 1, Before: initialState(), Request: maintenanceRequest(initialState())}
	for _, kind := range []string{"valid", "version", "owner", "no-results", "result-version", "result-count", "bytes", "core-version", "not-frozen", "partial-phase", "duplicate", "unknown", "trailing", "large", "unsupported", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			copied := record
			r := RuntimeResultsCloseReply{Version: 2, Maintenance: MaintenanceReply{Version: 1, Record: &copied, Control: Status{Version: 1, Committed: record.After(), Phase: "ready", DesiredMode: ModeDrained}}, Work: sandbox.AcceptedWorkStatus{Version: 1, Frozen: true}, Phase: "closed", Core: &sandbox.ResultBoundClosureObservation{Version: 2, Core: sandbox.ClosureObservation{Version: 1, Records: 1, RecordsSHA256: strings.Repeat("a", 64)}, Results: sandbox.ResultClosureObservation{Version: 2, Records: 1, Bytes: 100, ReservedBytes: 16384, RecordsSHA256: strings.Repeat("b", 64)}}, Sessions: &session.ClosureObservation{Version: 1, Records: 1, RecordsSHA256: strings.Repeat("c", 64)}}
			switch kind {
			case "version":
				r.Version = 1
			case "owner":
				copied.Request.Owner.OperationID = strings.Repeat("e", 32)
			case "no-results":
				r.Core.Results = sandbox.ResultClosureObservation{}
			case "result-version":
				r.Core.Results.Version = 1
			case "result-count":
				r.Core.Results.Records = -1
			case "bytes":
				r.Core.Results.Bytes = r.Core.Results.ReservedBytes + 1
			case "core-version":
				r.Core.Core.Version = 2
			case "not-frozen":
				r.Work.Frozen = false
			case "partial-phase":
				r.Phase = "closing-core"
			}
			data, _ := json.Marshal(r)
			switch kind {
			case "duplicate":
				data = append([]byte(`{"version":2,`), data[1:]...)
			case "unknown":
				data = append([]byte(`{"activation_allowed":true,`), data[1:]...)
			case "trailing":
				data = append(data, data...)
			case "large":
				data = []byte(strings.Repeat("x", MaxReplyBytes+1))
			}
			var calls atomic.Int64
			root := pinnedServer(t, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				calls.Add(1)
				if q.Method != "POST" || q.URL.Path != runtimeResultsClosePath {
					t.Error("wrong fixed endpoint")
				}
				switch kind {
				case "unsupported":
					w.WriteHeader(501)
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1:1/private")
					w.WriteHeader(307)
				default:
					w.Write(data)
				}
			}))
			client, e := NewPinnedClient(root, os.Getpid())
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			got, e := client.RuntimeResultsClose(context.Background(), record, true)
			if kind == "valid" {
				if e != nil || !got.valid() {
					t.Fatal(got, e)
				}
			} else if e == nil {
				t.Fatal("invalid/partial old proof accepted", kind)
			}
			if calls.Load() != 1 {
				t.Fatal("redirect/retry followed")
			}
		})
	}
}
