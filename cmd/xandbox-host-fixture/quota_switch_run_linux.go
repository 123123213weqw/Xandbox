//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"golang.org/x/sys/unix"
)

type switchRow struct {
	Iteration       int             `json:"iteration"`
	SessionOrdinal  int             `json:"session_ordinal"`
	WorkloadStartMS float64         `json:"workload_start_ms"`
	WorkloadEndMS   float64         `json:"workload_end_ms"`
	SwitchStartMS   float64         `json:"switch_start_ms"`
	SwitchEndMS     float64         `json:"switch_end_ms"`
	BindingMS       float64         `json:"request_to_binding_response_ms"`
	FirstCommandMS  float64         `json:"request_to_first_new_command_success_ms"`
	OldStoppedMS    float64         `json:"request_to_old_host_stopped_observed_ms"`
	OldDestroyedMS  float64         `json:"request_to_old_durable_destroyed_observed_ms"`
	Server          session.Timings `json:"server_phase_observations"`
	BusyOldRunning  bool            `json:"busy_old_job_running_at_switch_request"`
	BusyProgress    bool            `json:"busy_old_guest_write_progress_checked"`
	OldTimeoutMS    float64         `json:"old_job_earliest_timeout_budget_ms_at_switch_request"`
	OldJobTerminal  string          `json:"old_job_terminal"`
	Completed       bool            `json:"completed"`
}
type switchWorkerReport struct {
	Tenant       string                        `json:"tenant"`
	Rows         []switchRow                   `json:"samples"`
	FailureStage string                        `json:"failure_stage,omitempty"`
	Summary      map[string]map[string]float64 `json:"summary_ms,omitempty"`
}
type switchResource struct {
	ElapsedMS      float64 `json:"elapsed_ms"`
	DurationMS     float64 `json:"observation_duration_ms"`
	Allocated      uint64  `json:"allocated"`
	StopQueued     uint64  `json:"stop_queued"`
	CleanupQueued  uint64  `json:"cleanup_queued"`
	StopRunning    uint64  `json:"stop_running"`
	CleanupRunning uint64  `json:"cleanup_running"`
	OwnedCgroups   int     `json:"owned_cgroup_count"`
	Owners         int     `json:"durable_owner_files"`
	QuotaSpace     uint64  `json:"nontransactional_quota_space_bytes"`
	QuotaInodes    uint64  `json:"nontransactional_quota_inodes"`
	QuotaNonempty  int     `json:"nontransactional_nonempty_quota_slots"`
	CgroupMemory   uint64  `json:"instance_parent_memory_current_bytes"`
	RootFree       uint64  `json:"l1_root_free_bytes"`
	ControllerRSS  uint64  `json:"controller_rss_bytes"`
	ControllerFDs  int     `json:"controller_fd_count"`
}
type switchReport struct {
	Passed                               bool                  `json:"passed"`
	Cycles                               int                   `json:"cycles_per_tenant"`
	MinimumSeconds                       int                   `json:"minimum_paced_seconds"`
	RunBudgetSeconds                     int                   `json:"fixed_run_budget_seconds"`
	DurationSeconds                      float64               `json:"duration_seconds"`
	BusyWriterEverySwitch                bool                  `json:"busy_old_writer_each_switch"`
	Workers                              [2]switchWorkerReport `json:"workers"`
	Resources                            []switchResource      `json:"resources"`
	Overlaps                             int                   `json:"cross_tenant_overlapping_switch_interval_pairs"`
	FailureStage                         string                `json:"failure_stage,omitempty"`
	NoObserverSyncDuringMeasuredSwitches bool                  `json:"no_operator_quota_sync_during_measured_switches"`
	SameCreateKeyScopedPerTenant         bool                  `json:"same_initial_session_key_isolated_between_tenants"`
}

func switchMS(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }
func (c *switchAPI) openSession(ctx context.Context, key string) (session.Result, error) {
	var r session.Result
	e := c.call(ctx, "POST", "/v1/sessions", key, switchGuestSpec(), &r, 201)
	if e == nil && (!switchRefValid(r.Current) || !hex32Pattern(r.ID) || r.Revision != 1) {
		e = errors.New("invalid new session binding")
	}
	return r, e
}
func hex32Pattern(s string) bool { return len(s) == 32 && strings.Trim(s, "0123456789abcdef") == "" }
func (c *switchAPI) sessionJob(ctx context.Context, b session.Result, argv []string) (sandbox.Job, error) {
	var out struct {
		Revision uint64      `json:"revision"`
		Sandbox  sandbox.Ref `json:"sandbox"`
		Job      sandbox.Job `json:"job"`
	}
	e := c.call(ctx, "POST", "/v1/sessions/"+b.ID+"/exec", "", map[string]any{"revision": b.Revision, "argv": argv, "timeout_ms": 60000}, &out, 202)
	// Job.ID shadows its embedded Ref.ID on the public JSON wire. The separate
	// envelope supplies the sandbox ID; never compare a decoded Job.Ref as if
	// that missing field had been sent, or substitute the job ID for it.
	if e == nil && (out.Revision != b.Revision || out.Sandbox != b.Current || out.Job.Generation != b.Current.Generation || !hex32Pattern(out.Job.ID)) {
		e = errors.New("session execution bound to wrong generation")
	}
	if e == nil {
		out.Job.Ref = out.Sandbox
	}
	return out.Job, e
}
func (c *switchAPI) sessionExec(ctx context.Context, b session.Result, argv []string) (sandbox.Output, error) {
	j, e := c.sessionJob(ctx, b, argv)
	if e != nil {
		return sandbox.Output{}, e
	}
	return c.finish(ctx, b.Current, j)
}
func (c *switchAPI) revoke(ctx context.Context, b session.Result) error {
	var out struct {
		Revoked   bool `json:"admission_revoked"`
		Durable   bool `json:"durable"`
		Stopped   bool `json:"stop_confirmed"`
		Reclaimed bool `json:"reclamation_confirmed"`
	}
	if e := c.call(ctx, "POST", "/v1/sessions/"+b.ID+"/revoke", "", map[string]any{"expected_revision": b.Revision}, &out, 200); e != nil {
		return e
	}
	if !out.Revoked || out.Durable || out.Stopped || out.Reclaimed {
		return errors.New("revoke confused with durable stop/reclamation")
	}
	return c.destroyed(ctx, b.Current)
}
func switchFreshCommand() []string {
	return []string{"sh", "-c", "set -e; test ! -e mixed-marker; test ! -e mixed-disk; test ! -e /tmp/mixed-memory; test ! -e busy-switch-writer; test ! -e /tmp/busy-switch-sequence; id -u; cat /proc/sys/kernel/random/boot_id"}
}
func switchGuestIdentity(out sandbox.Output) (string, error) {
	f := strings.Fields(out.Stdout)
	if len(f) != 2 || f[0] != "65534" || !switchUUID(f[1]) {
		return "", errors.New("fresh guest identity mismatch")
	}
	return f[1], nil
}
func switchUUID(s string) bool {
	return len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' && len(strings.ReplaceAll(s, "-", "")) == 32 && strings.Trim(strings.ReplaceAll(s, "-", ""), "0123456789abcdef") == "" && strings.Trim(s, "0-") != ""
}
func switchOldJobStopped(j sandbox.Job) bool {
	if j.FinishedAt.IsZero() {
		return false
	}
	switch j.Status {
	case "CANCELLED", "FAILED":
		return true
	case "EXITED":
		return j.Output.ExitCode != 0
	}
	return false
}

func switchOldJobOutcome(j sandbox.Job, lookupErr error, row switchRow) (string, error) {
	for _, v := range []float64{row.OldStoppedMS, row.OldDestroyedMS, row.OldTimeoutMS} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return "", errors.New("invalid old execution proof observation")
		}
	}
	if !row.BusyProgress || !row.BusyOldRunning || row.OldTimeoutMS <= row.OldStoppedMS || row.OldDestroyedMS <= 0 || row.OldDestroyedMS < row.OldStoppedMS {
		return "", errors.New("independent pre-timeout stop and durable resource reclamation required")
	}
	if lookupErr != nil {
		var status *switchHTTPStatusError
		if errors.As(lookupErr, &status) && status.Got == 404 {
			return "HISTORY_DROPPED_AFTER_RECLAIM", nil
		}
		return "", lookupErr
	}
	if !switchOldJobStopped(j) {
		return "", errors.New("busy old writer terminal status invalid")
	}
	return j.Status, nil
}
func switchWorkload(tenant int) []string {
	ram, disk, rounds := 24, 8, 4
	if tenant == 1 {
		ram, disk, rounds = 4, 1, 1
	}
	return []string{"sh", "-c", fmt.Sprintf("set -e; dd if=/dev/zero of=/tmp/mixed-memory bs=1048576 count=%d 2>/dev/null; dd if=/dev/zero of=mixed-disk bs=1048576 count=%d 2>/dev/null; test $(wc -c < /tmp/mixed-memory) -eq %d; test $(wc -c < mixed-disk) -eq %d; sync; i=0; while [ $i -lt %d ]; do sha256sum /tmp/mixed-memory mixed-disk >/dev/null; i=$((i+1)); done; printf private > mixed-marker", ram, disk, ram<<20, disk<<20, rounds)}
}
func switchBusyWriter() []string {
	return []string{"sh", "-c", "set -e; i=0; while :; do dd if=/dev/zero of=busy-switch-writer bs=1048576 count=1 conv=notrunc 2>/dev/null; sync; i=$((i+1)); printf '%s\\n' \"$i\" > /tmp/busy-switch-sequence.new; mv /tmp/busy-switch-sequence.new /tmp/busy-switch-sequence; sleep 0.05; done"}
}
func switchBusyProgressCommand() []string {
	// A second ordinary guest execution proves actual writer progress. Merely
	// observing controller RUNNING would also accept a not-yet-dispatched job.
	return []string{"sh", "-c", "set -e; i=0; while [ ! -s /tmp/busy-switch-sequence ]; do i=$((i+1)); test $i -le 200; sleep 0.05; done; first=$(cat /tmp/busy-switch-sequence); case $first in ''|*[!0-9]*) exit 1;; esac; test \"$first\" -gt 0; i=0; while :; do next=$(cat /tmp/busy-switch-sequence); case $next in ''|*[!0-9]*) exit 1;; esac; if [ \"$next\" -gt \"$first\" ]; then break; fi; i=$((i+1)); test $i -le 200; sleep 0.05; done; test $(wc -c < busy-switch-writer) -eq 1048576"}
}
func switchDomainEmpty(ref sandbox.Ref) (bool, error) {
	if !switchRefValid(ref) {
		return false, errors.New("invalid fixed stop observation ref")
	}
	path := nodeGroup + "/" + ref.ID + ref.Generation + "/cgroup.events"
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return true, nil
	}
	if e != nil {
		// A cgroup can disappear after open and return ENODEV from read. Only
		// absence of this exact path permits that race to count as empty.
		if errors.Is(e, unix.ENODEV) {
			if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
				return true, nil
			}
		}
		return false, e
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "populated 0" {
			return true, nil
		}
		if line == "populated 1" {
			return false, nil
		}
	}
	return false, errors.New("missing actual cgroup populated counter")
}
func (c *switchAPI) waitBusy(ctx context.Context, b session.Result) (sandbox.Job, time.Time, error) {
	// The controller cannot start the execution timeout before this local
	// instant. Stop must be observed before this conservative lower bound.
	earliestTimeout := time.Now().Add(60 * time.Second)
	j, e := c.sessionJob(ctx, b, switchBusyWriter())
	if e != nil {
		return j, earliestTimeout, e
	}
	if _, e = c.sessionExec(ctx, b, switchBusyProgressCommand()); e != nil {
		return j, earliestTimeout, e
	}
	live, e := c.job(ctx, b.Current, j)
	if e != nil || live.Status != "RUNNING" {
		return j, earliestTimeout, errors.New("old writer not running after actual guest write progress")
	}
	return j, earliestTimeout, nil
}
func (n *node) switchWorker(ctx context.Context, tenant int, api *switchAPI, initial session.Result, began time.Time, out *switchWorkerReport) (err error) {
	stage := "initial"
	defer func() {
		if err != nil {
			out.FailureStage = stage
			fmt.Fprintln(os.Stderr, "private quota switch worker failure", tenant, stage, err)
		}
	}()
	binding := initial
	ordinal := 1
	first, e := api.sessionExec(ctx, binding, switchFreshCommand())
	if e != nil {
		return e
	}
	boot, e := switchGuestIdentity(first)
	if e != nil {
		return e
	}
	for i := 0; i < switchCycles; i++ {
		stage = "session_rotation"
		if i > 0 && i%48 == 0 {
			if e = api.revoke(ctx, binding); e != nil {
				return e
			}
			key, e := randomKey()
			if e != nil {
				return e
			}
			binding, e = api.openSession(ctx, key)
			if e != nil {
				return e
			}
			ordinal++
			first, e = api.sessionExec(ctx, binding, switchFreshCommand())
			if e != nil {
				return e
			}
			boot, e = switchGuestIdentity(first)
			if e != nil {
				return e
			}
		}
		out.Rows = append(out.Rows, switchRow{Iteration: i + 1, SessionOrdinal: ordinal, WorkloadStartMS: switchMS(began)})
		row := &out.Rows[len(out.Rows)-1]
		stage = "workload"
		if _, e = api.sessionExec(ctx, binding, switchWorkload(tenant)); e != nil {
			return e
		}
		row.WorkloadEndMS = switchMS(began)
		stage = "busy_old_job"
		oldJob, earliestTimeout, e := api.waitBusy(ctx, binding)
		if e != nil {
			return e
		}
		row.BusyOldRunning = true
		row.BusyProgress = true
		old := binding
		key, e := randomKey()
		if e != nil {
			return e
		}
		request := session.SwitchRequest{ExpectedRevision: old.Revision, Create: switchGuestSpec()}
		origin := time.Now()
		row.OldTimeoutMS = float64(earliestTimeout.Sub(origin).Microseconds()) / 1000
		if row.OldTimeoutMS <= 0 {
			return errors.New("old writer timeout budget exhausted before switch")
		}
		row.SwitchStartMS = switchMS(began)
		type stoppedResult struct {
			ms float64
			e  error
		}
		stopped := make(chan stoppedResult, 1)
		stopCtx, stopCancel := context.WithCancel(ctx)
		go func() {
			e := waitNode(stopCtx, func() (bool, error) { return switchDomainEmpty(old.Current) })
			stopped <- stoppedResult{switchMS(origin), e}
		}()
		stage = "switch"
		e = api.call(ctx, "POST", "/v1/sessions/"+old.ID+"/switch", key, request, &binding, 200)
		row.BindingMS = switchMS(origin)
		if e != nil {
			stopCancel()
			<-stopped
			return e
		}
		if binding.ID != old.ID || binding.Previous != old.Current || binding.Current == old.Current || binding.Revision != old.Revision+1 || !binding.Timings.Measured {
			stopCancel()
			<-stopped
			return errors.New("switch commit binding/timing mismatch")
		}
		stage = "first_new_command"
		first, e = api.sessionExec(ctx, binding, switchFreshCommand())
		row.FirstCommandMS = switchMS(origin)
		if e != nil {
			stopCancel()
			<-stopped
			return e
		}
		freshBoot, e := switchGuestIdentity(first)
		if e != nil || freshBoot == boot {
			stopCancel()
			<-stopped
			return errors.New("new candidate restored assigned guest")
		}
		boot = freshBoot
		stage = "old_physical_stop"
		observed := <-stopped
		stopCancel()
		if observed.e != nil {
			return observed.e
		}
		row.OldStoppedMS = observed.ms
		if row.OldStoppedMS >= row.OldTimeoutMS {
			return errors.New("old execution stop not independent of job timeout")
		}
		stage = "old_durable_destroyed"
		if e = api.destroyed(ctx, old.Current); e != nil {
			return e
		}
		row.OldDestroyedMS = switchMS(origin)
		terminal, e := api.job(ctx, old.Current, oldJob)
		// Ordinary manager deliberately drops ephemeral history at durable
		// DESTROYED. A 404 is not a job terminal status or standalone Stop
		// proof; independent host-empty/deadline/reclamation must pass first.
		row.OldJobTerminal, e = switchOldJobOutcome(terminal, e, *row)
		if e != nil {
			return e
		}
		stage = "new_generation_quota"
		if _, e = n.switchReady(binding.Current, false); e != nil {
			return e
		}
		stage = "replay_and_revocation"
		var replay session.Result
		if e = api.call(ctx, "POST", "/v1/sessions/"+old.ID+"/switch", key, request, &replay, 200); e != nil {
			return e
		}
		if replay.ID != binding.ID || replay.Current != binding.Current || replay.Previous != binding.Previous || replay.Revision != binding.Revision {
			return errors.New("switch key replay allocated another candidate")
		}
		if e = api.call(ctx, "POST", "/v1/sessions/"+binding.ID+"/exec", "", map[string]any{"revision": old.Revision, "argv": []string{"true"}}, nil, 409); e != nil {
			return e
		}
		staleKey, e := randomKey()
		if e != nil {
			return e
		}
		if e = api.call(ctx, "POST", "/v1/sessions/"+binding.ID+"/switch", staleKey, request, nil, 409); e != nil {
			return e
		}
		if e = api.call(ctx, "POST", switchPath(binding.Current)+"/exec", "", sandbox.ExecRequest{Generation: binding.Current.Generation, Argv: []string{"true"}}, nil, 409); e != nil {
			return e
		}
		row.Server = binding.Timings
		row.SwitchEndMS = switchMS(began)
		row.Completed = true
		stage = "pacing"
		deadline := began.Add(time.Duration(switchMinimumSeconds) * time.Second * time.Duration(i+1) / switchCycles)
		if wait := time.Until(deadline); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	stage = "final_revoke"
	return api.revoke(ctx, binding)
}
func switchQuantiles(rows []switchRow) map[string]map[string]float64 {
	out := map[string]map[string]float64{}
	for k, get := range map[string]func(switchRow) float64{"binding": func(r switchRow) float64 { return r.BindingMS }, "first_new_command": func(r switchRow) float64 { return r.FirstCommandMS }, "old_host_stopped": func(r switchRow) float64 { return r.OldStoppedMS }, "old_durable_destroyed": func(r switchRow) float64 { return r.OldDestroyedMS }} {
		values := make([]float64, len(rows))
		for i, r := range rows {
			values[i] = get(r)
		}
		sort.Float64s(values)
		q := map[string]float64{"count": float64(len(rows))}
		for _, p := range []int{50, 95, 99, 100} {
			if len(values) > 0 {
				q[fmt.Sprint("p", p)] = values[int(math.Ceil(float64(len(values))*float64(p)/100))-1]
			}
		}
		out[k] = q
	}
	return out
}
func switchParseGauges(text string) (map[string]uint64, error) {
	out := map[string]uint64{}
	for _, name := range []string{"allocated", "stop_queued", "cleanup_queued", "stop_running", "cleanup_running"} {
		prefix := "xandbox_" + name + " "
		count := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, prefix) {
				value, e := strconv.ParseUint(strings.TrimPrefix(line, prefix), 10, 64)
				if e != nil {
					return nil, e
				}
				out[name] = value
				count++
			}
		}
		if count != 1 {
			return nil, errors.New("missing/duplicate fixed gauge")
		}
	}
	return out, nil
}
func switchGauges(ctx context.Context) (map[string]uint64, error) {
	c := newSwitchAPI("/srv/state/metrics.sock", "")
	defer c.close()
	req, e := httpRequestMetrics(ctx)
	if e != nil {
		return nil, e
	}
	r, e := c.http.Do(req)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	b, e := readSwitchMetrics(r.Body)
	if e != nil {
		return nil, e
	}
	if r.StatusCode != 200 {
		return nil, errors.New("fixed metrics unavailable")
	}
	return switchParseGauges(string(b))
}
func (n *node) switchResourceSample(ctx context.Context, began time.Time, identity string) (switchResource, error) {
	start := time.Now()
	row := switchResource{ElapsedMS: switchMS(began)}
	got, e := processStart(n.process.Process.Pid)
	if e != nil || got != identity {
		return row, errors.New("switch controller incarnation changed")
	}
	gauges, e := switchGauges(ctx)
	if e != nil {
		return row, e
	}
	row.Allocated = gauges["allocated"]
	row.StopQueued = gauges["stop_queued"]
	row.CleanupQueued = gauges["cleanup_queued"]
	row.StopRunning = gauges["stop_running"]
	row.CleanupRunning = gauges["cleanup_running"]
	if row.Allocated > switchCapacity {
		return row, errors.New("observed node allocated capacity exceeded")
	}
	groups, e := os.ReadDir(nodeGroup)
	if e != nil {
		return row, e
	}
	for _, d := range groups {
		if d.IsDir() && len(d.Name()) == 64 && strings.Trim(d.Name(), "0123456789abcdef") == "" {
			row.OwnedCgroups++
		}
	}
	owners, e := os.ReadDir("/srv/state/firecracker")
	if e != nil {
		return row, e
	}
	for _, d := range owners {
		name := strings.TrimSuffix(d.Name(), ".json")
		if !d.IsDir() && len(name) == 64 && strings.Trim(name, "0123456789abcdef") == "" {
			row.Owners++
		}
	}
	q, e := openQuotaFS(false)
	if e != nil {
		return row, e
	}
	for id := driverProjectFirst; id < driverProjectFirst+switchSlots; id++ {
		r, e := switchQuotaRead(q, id)
		if e != nil {
			q.file.Close()
			return row, e
		}
		if !switchKnown(r) {
			q.file.Close()
			return row, errors.New("sampled quota drift")
		}
		row.QuotaSpace += r.Space
		row.QuotaInodes += r.Inodes
		if !quotaEmpty(r) {
			row.QuotaNonempty++
		}
	}
	q.file.Close()
	b, e := os.ReadFile(nodeGroup + "/memory.current")
	if e != nil {
		return row, e
	}
	row.CgroupMemory, e = switchUint(string(b))
	if e != nil {
		return row, e
	}
	var fs unix.Statfs_t
	if e = unix.Statfs("/srv", &fs); e != nil {
		return row, e
	}
	row.RootFree = fs.Bavail * uint64(fs.Bsize)
	if row.RootFree < 256<<20 {
		return row, errors.New("bounded experiment root free-space reserve exhausted")
	}
	b, e = os.ReadFile(fmt.Sprintf("/proc/%d/status", n.process.Process.Pid))
	if e != nil {
		return row, e
	}
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmRSS:" && fields[2] == "kB" {
			v, e := switchUint(fields[1])
			if e != nil {
				return row, e
			}
			row.ControllerRSS = v * 1024
			found = true
		}
	}
	if !found {
		return row, errors.New("controller RSS unavailable")
	}
	fds, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", n.process.Process.Pid))
	if e != nil {
		return row, e
	}
	row.ControllerFDs = len(fds)
	got, e = processStart(n.process.Process.Pid)
	if e != nil || got != identity {
		return row, errors.New("controller changed during resource sample")
	}
	row.DurationMS = switchMS(start)
	return row, nil
}
func (n *node) quotaSwitchRun(ctx context.Context) (out map[string]any, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaSwitch || n.process == nil || !hashPattern.MatchString(n.switchTemplate) {
		return nil, errors.New("prepared switch node required")
	}
	marker, e := os.OpenFile("/srv/fixture/quota-switch-run-started", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, errors.New("switch workload cannot be restarted in the same fixture incarnation")
	}
	if e = marker.Sync(); e != nil {
		marker.Close()
		return nil, e
	}
	marker.Close()
	began := time.Now()
	report := &switchReport{Cycles: switchCycles, MinimumSeconds: switchMinimumSeconds, RunBudgetSeconds: int(switchRunBudget / time.Second), BusyWriterEverySwitch: true, Resources: []switchResource{}, NoObserverSyncDuringMeasuredSwitches: true}
	report.Workers[0] = switchWorkerReport{Tenant: "alpha", Rows: []switchRow{}}
	report.Workers[1] = switchWorkerReport{Tenant: "beta", Rows: []switchRow{}}
	out = map[string]any{"phase": "quota-enabled-two-tenant-switching", "load": report}
	stage := "initial_sessions"
	defer func() {
		if report.DurationSeconds == 0 {
			report.DurationSeconds = time.Since(began).Seconds()
		}
		if err != nil {
			report.FailureStage = stage
		}
	}()
	api := n.switchClients()
	defer api[0].close()
	defer api[1].close()
	key, e := randomKey()
	if e != nil {
		return out, e
	}
	var bindings [2]session.Result
	for i := 0; i < 2; i++ {
		bindings[i], e = api[i].openSession(ctx, key)
		if e != nil {
			return out, e
		}
		if _, e = n.switchReady(bindings[i].Current, false); e != nil {
			return out, e
		}
	}
	if bindings[0].ID == bindings[1].ID || bindings[0].Current == bindings[1].Current {
		return out, errors.New("same create key crossed tenants")
	}
	if e = api[0].call(ctx, "GET", "/v1/sessions/"+bindings[1].ID, "", nil, nil, 404); e != nil {
		return out, e
	}
	report.SameCreateKeyScopedPerTenant = true
	identity, e := processStart(n.process.Process.Pid)
	if e != nil {
		return out, e
	}
	first, e := n.switchResourceSample(ctx, began, identity)
	if e != nil {
		return out, e
	}
	report.Resources = append(report.Resources, first)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	sampleCtx, stopSample := context.WithCancel(ctx)
	defer stopSample()
	sampleDone := make(chan struct{})
	sampleError := make(chan error, 1)
	go func() {
		defer close(sampleDone)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-sampleCtx.Done():
				return
			case <-tick.C:
				row, e := n.switchResourceSample(sampleCtx, began, identity)
				if e != nil {
					if sampleCtx.Err() == nil {
						sampleError <- e
						cancel()
					}
					return
				}
				if len(report.Resources) >= switchSampleLimit {
					sampleError <- errors.New("fixed sample count bound exceeded")
					cancel()
					return
				}
				report.Resources = append(report.Resources, row)
			}
		}
	}()
	stage = "workers"
	var wg sync.WaitGroup
	workerErrors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := n.switchWorker(runCtx, i, api[i], bindings[i], began, &report.Workers[i])
			if e != nil {
				cancel()
			}
			workerErrors <- e
		}(i)
	}
	wg.Wait()
	stopSample()
	<-sampleDone
	close(workerErrors)
	for e := range workerErrors {
		if e != nil {
			return out, e
		}
	}
	select {
	case e := <-sampleError:
		return out, e
	default:
	}
	stage = "drain"
	if e = waitNode(ctx, func() (bool, error) {
		g, e := switchGauges(ctx)
		if e != nil {
			return false, e
		}
		for _, v := range g {
			if v != 0 {
				return false, nil
			}
		}
		return true, nil
	}); e != nil {
		return out, e
	}
	if e = switchAllClear(); e != nil {
		return out, e
	}
	final, e := n.switchResourceSample(ctx, began, identity)
	if e != nil {
		return out, e
	}
	if final.Owners != 0 || final.OwnedCgroups != 0 || final.QuotaNonempty != 0 || final.QuotaSpace != 0 || final.QuotaInodes != 0 {
		return out, errors.New("switch final private ownership not drained")
	}
	report.Resources = append(report.Resources, final)
	for i := 0; i < 2; i++ {
		if len(report.Workers[i].Rows) != switchCycles {
			return out, errors.New("missing switch rows")
		}
		for _, r := range report.Workers[i].Rows {
			if !r.Completed || !r.BusyOldRunning || !r.BusyProgress || r.OldStoppedMS >= r.OldTimeoutMS {
				return out, errors.New("incomplete switch row")
			}
		}
		report.Workers[i].Summary = switchQuantiles(report.Workers[i].Rows)
	}
	for _, a := range report.Workers[0].Rows {
		for _, b := range report.Workers[1].Rows {
			if a.SwitchStartMS < b.SwitchEndMS && b.SwitchStartMS < a.SwitchEndMS {
				report.Overlaps++
			}
		}
	}
	if report.Overlaps == 0 || time.Since(began) < switchMinimumSeconds*time.Second {
		return out, errors.New("no actual overlap or pacing duration")
	}
	report.DurationSeconds = time.Since(began).Seconds()
	// Export the large load report BEFORE starting any crash-checkpoint jobs.
	// UART serialization is not charged against their fixed60s execution TTL.
	done, e := os.OpenFile("/srv/fixture/quota-switch-load-complete", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return out, e
	}
	if e = done.Sync(); e != nil {
		done.Close()
		return out, e
	}
	done.Close()
	report.Passed = true
	return out, nil
}

func httpRequestMetrics(ctx context.Context) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, "GET", "http://operator.local/metrics", nil)
}
func readSwitchMetrics(r io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, (256<<10)+1))
	if e != nil {
		return nil, e
	}
	if len(b) > 256<<10 {
		return nil, errors.New("bounded metrics response exceeded")
	}
	return b, nil
}
