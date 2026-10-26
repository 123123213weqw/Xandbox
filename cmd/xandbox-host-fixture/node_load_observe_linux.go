//go:build linux && xandbox_host_fixture

package main

// TEST ONLY read-only observations of the exact owned L1. No ptrace, filesystem
// sync, controller mutation, retry of work, or host-execution fallback.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

const nodeLoadProbeAfter = 20 * time.Second
const nodeLoadProbeSlots = 8
const nodeLoadProbeBudget = 2 * time.Second

func nodeLoadPairs(b []byte) (map[string]uint64, error) {
	out := map[string]uint64{}
	if len(b) > 65536 {
		return nil, errors.New("bounded kernel counter file required")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, errors.New("invalid kernel counter row")
		}
		if _, ok := out[f[0]]; ok {
			return nil, errors.New("duplicate kernel counter row")
		}
		v, e := strconv.ParseUint(f[1], 10, 64)
		if e != nil {
			return nil, e
		}
		out[f[0]] = v
	}
	return out, nil
}
func nodeLoadIO(b []byte, device string) (map[string]uint64, error) {
	out := map[string]uint64{"observed": 0, "rbytes": 0, "wbytes": 0, "rios": 0, "wios": 0}
	if len(b) > 65536 {
		return nil, errors.New("bounded IO stat required")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != device {
			continue
		}
		if out["observed"] != 0 {
			return nil, errors.New("duplicate exact IO device")
		}
		seen := map[string]bool{}
		for _, field := range f[1:] {
			kv := strings.Split(field, "=")
			if len(kv) != 2 || seen[kv[0]] {
				return nil, errors.New("invalid IO stat pair")
			}
			seen[kv[0]] = true
			n, e := strconv.ParseUint(kv[1], 10, 64)
			if e != nil {
				return nil, e
			}
			if _, ok := out[kv[0]]; ok && kv[0] != "observed" {
				out[kv[0]] = n
			}
		}
		for _, key := range []string{"rbytes", "wbytes", "rios", "wios"} {
			if !seen[key] {
				return nil, errors.New("incomplete IO device row")
			}
		}
		out["observed"] = 1
	}
	return out, nil
}
func (n *node) nodeLoadKernelCounters(metrics []byte) (map[string]uint64, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.nodeLoad || n.process == nil {
		return nil, errors.New("owned load controller required")
	}
	c, e := fixedNodeLoadConfig()
	if e != nil {
		return nil, e
	}
	out := map[string]uint64{}
	for _, p := range []struct{ name, path string }{{"node", nodeGroup}, {"control", nodeGroup + "/control"}} {
		b, e := os.ReadFile(p.path + "/pids.current")
		if e != nil {
			return nil, e
		}
		v, e := switchUint(string(b))
		if e != nil {
			return nil, e
		}
		out[p.name+"_pids"] = v
		b, e = os.ReadFile(p.path + "/pids.events")
		if e != nil {
			return nil, e
		}
		pairs, e := nodeLoadPairs(b)
		if e != nil {
			return nil, e
		}
		v, ok := pairs["max"]
		if !ok {
			return nil, errors.New("missing pids max event")
		}
		out[p.name+"_pids_max_events"] = v
		b, e = os.ReadFile(p.path + "/cpu.stat")
		if e != nil {
			return nil, e
		}
		pairs, e = nodeLoadPairs(b)
		if e != nil {
			return nil, e
		}
		for _, key := range []string{"usage_usec", "throttled_usec", "nr_throttled"} {
			v, ok := pairs[key]
			if !ok {
				return nil, errors.New("missing CPU counter")
			}
			out[p.name+"_cpu_"+key] = v
		}
		b, e = os.ReadFile(p.path + "/io.stat")
		if e != nil {
			return nil, e
		}
		vIO, e := nodeLoadIO(b, c.IO.Device)
		if e != nil {
			return nil, e
		}
		for key, v := range vIO {
			out[p.name+"_io_"+key] = v
		}
	}
	for _, reason := range []string{"io", "quota", "other"} {
		v, e := nodeLoadMetric(string(metrics), `xandbox_prepare_failed_total{reason="`+reason+`"}`)
		if e != nil {
			return nil, e
		}
		out["prepare_failed_"+reason] = v
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", n.process.Process.Pid))
	if e != nil {
		return nil, e
	}
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "Threads:" {
			if found {
				return nil, errors.New("duplicate thread count")
			}
			v, e := strconv.ParseUint(f[1], 10, 64)
			if e != nil {
				return nil, e
			}
			out["controller_threads"] = v
			found = true
		}
	}
	if !found {
		return nil, errors.New("missing actual controller thread count")
	}
	return out, nil
}

// Existing fixed gauges sampled in the SAME metrics response, privately. They
// are not a linearized view or a per-actor capacity/driver-wait attribution.
func nodeLoadCapacityMetrics(metrics []byte) (map[string]uint64, error) {
	out := map[string]uint64{}
	for _, entry := range []struct{ name, metric string }{
		{"queued", "xandbox_create_queued"}, {"capacity", "xandbox_create_queue_capacity"},
		{"class_capacity", "xandbox_create_queue_capacity_per_class"},
	} {
		value, e := nodeLoadMetric(string(metrics), entry.metric)
		if e != nil {
			return nil, e
		}
		out[entry.name] = value
	}
	class := uint64(min(128, nodeLoadPolicy().MaxInstances))
	if out["class_capacity"] != class || out["capacity"] != 2*class || out["queued"] > out["capacity"] {
		return nil, errors.New("fixed capacity queue gauge bounds required")
	}
	return out, nil
}

// This shadow channel is PRIVATE even on a passing run. Python detaches it
// before the public result validator; raw LastError text never reaches metrics.
type nodeLoadDiagnosticRow struct {
	Sequence uint64 `json:"sequence"`
	Kind     uint8  `json:"kind"`
	Reason   uint8  `json:"reason"`
	TimeNS   int64  `json:"time_unix_ns"`
	Dropped  uint64 `json:"dropped_before"`
}
type nodeLoadObservation struct {
	StreamKind            int                     `json:"stream_kind"`
	IntentIndex           int                     `json:"intent_index"`
	Tenant                int                     `json:"tenant"`
	DiagnosticReadOK      bool                    `json:"diagnostic_read_ok"`
	LedgerScanTruncated   bool                    `json:"ledger_scan_truncated"`
	LedgerCandidates      int                     `json:"ledger_candidates"`
	LedgerInspected       int                     `json:"ledger_inspected"`
	LedgerReadErrors      int                     `json:"ledger_read_errors"`
	Available             bool                    `json:"available"`
	ElapsedMS             float64                 `json:"elapsed_ms"`
	OfferedOriginKnown    bool                    `json:"offered_origin_known"`
	CaptureMS             float64                 `json:"capture_ms"`
	Complete              bool                    `json:"complete"`
	RecordFound           bool                    `json:"record_found"`
	RecordState           string                  `json:"record_state"`
	Owner                 bool                    `json:"owner_present"`
	Group                 bool                    `json:"cgroup_present"`
	Jail                  bool                    `json:"jail_present"`
	Workspace             bool                    `json:"workspace_present"`
	APISocket             bool                    `json:"api_socket_present"`
	VSocket               bool                    `json:"vsocket_present"`
	WorkspaceLogicalBytes int64                   `json:"workspace_logical_bytes"`
	LastError             string                  `json:"last_error_private"`
	RecentErrors          []string                `json:"recent_errors_private"`
	Kernel                map[string]uint64       `json:"kernel"`
	Capacity              map[string]uint64       `json:"capacity"`
	DiagnosticSequence    uint64                  `json:"diagnostic_sequence"`
	DiagnosticRecords     []nodeLoadDiagnosticRow `json:"diagnostic_records"`
	PID1                  *nodeLoadCensus         `json:"pid1_census"`
}
type nodeLoadPrivateDiagnostics struct {
	Actors          nodeLoadActorsSnapshot `json:"actors"`
	Slow            []nodeLoadObservation  `json:"slow"`
	Omitted         int                    `json:"omitted"`
	Failure         *nodeLoadObservation   `json:"failure"`
	PreflightBefore *nodeLoadCensus        `json:"pid1_preflight_before"`
	PreflightAfter  *nodeLoadCensus        `json:"pid1_preflight_after"`
}

func nodeLoadClip(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	// Keep valid UTF-8 for bounded JSON; no raw text is ever published.
	return strings.ToValidUTF8(s, "?")
}
func (n *node) nodeLoadObserve(ctx context.Context, tenant int, key, identity string, start time.Time) nodeLoadObservation {
	out := nodeLoadObservation{StreamKind: -1, IntentIndex: -1, Tenant: tenant, OfferedOriginKnown: !start.IsZero()}
	if out.OfferedOriginKnown {
		out.ElapsedMS = switchMS(start)
	}
	began := time.Now()
	if requireNode() != nil || !n.nodeLoad || n.process == nil {
		return out
	}
	got, e := processStart(n.process.Process.Pid)
	if e != nil || got != identity {
		return out
	}
	out.Available = true
	finish := func() nodeLoadObservation {
		out.CaptureMS = switchMS(began)
		return out
	}
	entries, e := os.ReadDir("/srv/state/ledger")
	if e != nil || len(entries) > 10000 {
		return finish()
	}
	type candidate struct {
		name string
		at   time.Time
	}
	candidates := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if ctx.Err() != nil {
			return finish()
		}
		if !hex32Pattern(strings.TrimSuffix(entry.Name(), ".json")) || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			continue
		}
		if info.ModTime().Before(began.Add(-40 * time.Second)) {
			continue
		}
		candidates = append(candidates, candidate{entry.Name(), info.ModTime()})
	}
	out.LedgerCandidates = len(candidates)
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].at.After(candidates[j].at) })
	sum := sha256.Sum256([]byte(key))
	digest := hex.EncodeToString(sum[:])
	for i, entry := range candidates {
		if ctx.Err() != nil {
			return finish()
		}
		if i >= 64 {
			out.LedgerScanTruncated = true
			break
		}
		out.LedgerInspected++
		b, e := privatefile.Read(filepath.Join("/srv/state/ledger", entry.name), sandbox.MaxLedgerRecordBytes)
		if e != nil {
			out.LedgerReadErrors++
			continue
		}
		var env struct {
			Version int             `json:"version"`
			Record  *sandbox.Record `json:"record"`
		}
		if strictjson.Decode(b, &env) != nil || env.Version != 1 || env.Record == nil {
			continue
		}
		record := env.Record
		if key == "" {
			if record.LastError != "" && len(out.RecentErrors) < 4 {
				out.RecentErrors = append(out.RecentErrors, nodeLoadClip(record.LastError))
			}
			continue
		}
		if tenant < 0 || tenant > 1 || record.TenantID != nodeLoadTenants[tenant] || record.CreateKeyHash != digest || !switchRefValid(record.Ref) {
			continue
		}
		out.RecordFound = true
		out.RecordState = string(record.State)
		out.LastError = nodeLoadClip(record.LastError)
		suffix := record.Ref.ID + record.Ref.Generation
		root := "/srv/r/j/firecracker/" + suffix + "/root"
		present := func(path string) bool { _, e := os.Lstat(path); return e == nil }
		out.Owner = present("/srv/state/firecracker/" + suffix + ".json")
		out.Group = present(nodeBudgetInstances + "/" + suffix)
		out.Jail = present(filepath.Dir(root))
		out.Workspace = present(root + "/workspace.ext4")
		out.APISocket = present(root + "/api.sock")
		out.VSocket = present(root + "/v.sock")
		if info, e := os.Lstat(root + "/workspace.ext4"); e == nil && info.Mode().IsRegular() {
			out.WorkspaceLogicalBytes = info.Size()
		}
		break
	}
	// Read the existing bounded, CRC-validated diagnostic ring; never Start/Load
	// a second controller/store, take locks, or rewrite the journal.
	if ctx.Err() != nil {
		return finish()
	}
	if snap, e := diagnostics.Read("/srv/state/diagnostics"); e == nil {
		out.DiagnosticReadOK = true
		out.DiagnosticSequence = snap.ObservedSequence
		records := snap.Records
		if len(records) > 16 {
			records = records[len(records)-16:]
		}
		for _, r := range records {
			out.DiagnosticRecords = append(out.DiagnosticRecords, nodeLoadDiagnosticRow{r.Sequence, uint8(r.Event.Kind), uint8(r.Event.Reason), r.Event.TimeNS, r.Event.DroppedBefore})
		}
	}
	if ctx.Err() != nil {
		return finish()
	}
	api := newSwitchAPI("/srv/state/metrics.sock", "")
	defer api.close()
	req, e := httpRequestMetrics(ctx)
	if e != nil {
		return finish()
	}
	resp, e := api.http.Do(req)
	if e != nil {
		return finish()
	}
	b, e := readSwitchMetrics(resp.Body)
	resp.Body.Close()
	if e == nil && resp.StatusCode == 200 {
		out.Kernel, _ = n.nodeLoadKernelCounters(b)
		out.Capacity, _ = nodeLoadCapacityMetrics(b)
	}
	census := n.nodeLoadPID1Census(ctx, identity)
	out.PID1 = &census
	got, e = processStart(n.process.Process.Pid)
	if e != nil || got != identity {
		out.Available = false
	}
	out.Complete = out.Available && out.Kernel != nil && out.Capacity != nil && census.Complete && out.DiagnosticReadOK && !out.LedgerScanTruncated && out.LedgerReadErrors == 0 && ctx.Err() == nil
	return finish()
}

func (s *nodeLoadState) nodeLoadProbe(ctx context.Context, trigger <-chan time.Time, tenant int, key string, kind, index int) func() {
	watch, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-watch.Done():
			return
		case <-trigger:
		}
		s.mu.Lock()
		if s.observe == nil {
			s.mu.Unlock()
			return
		}
		if s.probesStarted >= nodeLoadProbeSlots {
			s.probesOmitted++
			s.mu.Unlock()
			return
		}
		s.probesStarted++
		observe := s.observe
		s.mu.Unlock()
		bounded, stop := context.WithTimeout(watch, nodeLoadProbeBudget)
		out := observe(bounded, tenant, key)
		out.StreamKind, out.IntentIndex, out.Tenant = kind, index, tenant
		stop()
		s.mu.Lock()
		s.privateDiagnostics.Slow = append(s.privateDiagnostics.Slow, out)
		s.mu.Unlock()
	}()
	return func() { cancel(); <-done }
}
func (s *nodeLoadState) startCreateProbe(ctx context.Context, tenant int, key string, kind, index int) func() {
	s.mu.Lock()
	enabled := s.observe != nil
	s.mu.Unlock()
	if !enabled {
		return func() {}
	}
	timer := time.NewTimer(nodeLoadProbeAfter)
	stop := s.nodeLoadProbe(ctx, timer.C, tenant, key, kind, index)
	return func() { timer.Stop(); stop() }
}
func (s *nodeLoadState) captureFailure(ctx context.Context) {
	s.mu.Lock()
	observe := s.observe
	already := s.privateDiagnostics.Failure != nil
	s.mu.Unlock()
	if observe == nil || already {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, nodeLoadProbeBudget)
	out := observe(bounded, -1, "")
	cancel()
	s.mu.Lock()
	if s.firstRow != nil {
		out.StreamKind, out.IntentIndex, out.Tenant = s.firstRow.Kind, s.firstRow.Index, s.firstRow.Tenant
	}
	s.mu.Unlock()
	s.mu.Lock()
	if s.privateDiagnostics.Failure == nil {
		s.privateDiagnostics.Failure = &out
	}
	s.mu.Unlock()
}

// A runtime size check keeps the entire private capsule well below the
// one-MiB wire frame even with escaped raw error text and all resource samples.
func nodeLoadPrivateBound(v nodeLoadPrivateDiagnostics) error {
	b, e := json.Marshal(v)
	if e != nil || len(b) > 192<<10 {
		return errors.New("bounded private diagnostic capsule exceeded")
	}
	return nil
}
