//go:build linux && xandbox_host_fixture

package main

// TEST ONLY, explicitly opted in: eight fixed syscall tracepoints plus fixed task lineage in our owned L1.
// No production code/hooks, user-memory reads, dynamic probes or L0 tracing.
// The workload is the full original node-budget baseline, NOT open40m and
// NOT a production qualification or a causal speedup claim.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const costTraceInstance = prepareTraceRoot + "/instances/xandbox_creation_cost_v4"
const costTraceMax = 512 << 10

var costTraceEvents = []string{"syscalls/sys_enter_quotactl_fd", "syscalls/sys_exit_quotactl_fd", "syscalls/sys_enter_syncfs", "syscalls/sys_exit_syncfs", "syscalls/sys_enter_fsync", "syscalls/sys_exit_fsync", "syscalls/sys_enter_sync_file_range", "syscalls/sys_exit_sync_file_range", "task/task_newtask"}

type creationCostTrace struct {
	diagnosticMode                                          creationCostMode
	scope, ordinaryELF                                      string
	window                                                  int64
	creates                                                 []costCreateElapsed
	createInFlight, published, abortPublished, abiQualified bool
	initialAnchors                                          map[string]map[string]uint64
	target                                                  prepareTrace
	mounted, instance, stopped, closed                      bool
	enabled                                                 []string
	initialTasks                                            []string
	formats                                                 map[string]string
}

func costRead(path string, limit int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b := make([]byte, 0, limit)
	buf := make([]byte, 4096)
	for {
		n, e := f.Read(buf)
		if n > 0 {
			if len(b) > limit-n {
				return nil, errors.New("bounded cost observation exceeded")
			}
			b = append(b, buf[:n]...)
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				return b, nil
			}
			return nil, e
		}
		if n == 0 {
			return nil, errors.New("empty cost observation read")
		}
	}
}
func (t *creationCostTrace) resume() error {
	if !t.stopped {
		return nil
	}
	if e := t.target.daemon(); e != nil {
		return e
	}
	if e := unix.Kill(t.target.pid, unix.SIGCONT); e != nil {
		return e
	}
	t.stopped = false
	return nil
}
func costSelectedSyscall(raw []byte) (bool, error) {
	fields := strings.Fields(string(raw))
	if len(fields) < 1 {
		return false, errors.New("missing stopped syscall state")
	}
	id, e := strconv.ParseInt(fields[0], 10, 64)
	if e != nil {
		return false, e
	}
	if (id == -1 && len(fields) != 3) || (id >= 0 && len(fields) != 9) || id < -1 {
		return false, errors.New("noncanonical stopped syscall fields")
	}
	for _, value := range fields[1:] {
		if !strings.HasPrefix(value, "0x") {
			return false, errors.New("noncanonical stopped syscall register")
		}
		if _, e := strconv.ParseUint(value[2:], 16, 64); e != nil {
			return false, e
		}
	}
	return id == unix.SYS_FSYNC || id == unix.SYS_SYNCFS || id == unix.SYS_QUOTACTL_FD || id == unix.SYS_SYNC_FILE_RANGE, nil
}
func (t *creationCostTrace) freeze() ([]string, error) {
	if e := t.target.daemon(); e != nil {
		return nil, e
	}
	if e := unix.Kill(t.target.pid, unix.SIGSTOP); e != nil {
		return nil, e
	}
	t.stopped = true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var tids []string
	e := waitNode(ctx, func() (bool, error) {
		entries, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", t.target.pid))
		if e != nil {
			return false, e
		}
		if len(entries) == 0 || len(entries) > 128 {
			return false, errors.New("fixed daemon thread bound")
		}
		var current []string
		for _, entry := range entries {
			if _, e := strconv.ParseUint(entry.Name(), 10, 32); e != nil {
				return false, e
			}
			b, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/stat", t.target.pid, entry.Name()))
			if e != nil {
				return false, e
			}
			at := bytes.LastIndex(b, []byte(") "))
			if at < 0 {
				return false, errors.New("invalid stopped stat")
			}
			f := strings.Fields(string(b[at+2:]))
			if len(f) < 20 {
				return false, errors.New("short stopped stat")
			}
			if f[0] != "T" {
				return false, nil
			}
			current = append(current, entry.Name())
		}
		sort.Strings(current)
		tids = current
		return true, nil
	})
	if e != nil {
		return nil, e
	}
	// Do not begin/end a timing window through an already in-flight selected
	// syscall. A violated setup precondition FAILS rather than losing a pair.
	for _, tid := range tids {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/syscall", t.target.pid, tid))
		if e != nil {
			return nil, e
		}
		selected, e := costSelectedSyscall(b)
		if e != nil {
			return nil, e
		}
		if selected {
			return nil, errors.New("selected syscall active at observation boundary")
		}
	}
	return tids, t.target.daemon()
}
func startCreationCostTrace(pid int, scope string) (*creationCostTrace, error) {
	return startCreationCostTraceForMode(configuredCreationCostMode, pid, scope)
}
func startCreationCostTraceForMode(mode creationCostMode, pid int, scope string) (*creationCostTrace, error) {
	return withCreationCostMode(mode, func() (*creationCostTrace, error) { return startEnabledCreationCostTrace(mode, pid, scope) })
}
func startEnabledCreationCostTrace(mode creationCostMode, pid int, scope string) (t *creationCostTrace, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if _, e := fixedBudgetConfig(); e != nil {
		return nil, e
	}
	h, e := fileHash("/srv/assets/sandboxd")
	if e != nil {
		return nil, e
	}
	window, e := costWindowForELF(h)
	if e != nil {
		return nil, e
	}
	if scope != "checkpoint" && scope != "cold" {
		return nil, errors.New("fixed cost scope required")
	}
	var u unix.Utsname
	if e = unix.Uname(&u); e != nil || unix.ByteSliceToString(u.Release[:]) != "6.8.0-136-generic" {
		return nil, errors.New("fixed owned L1 kernel required")
	}
	cpus, e := os.ReadFile("/sys/devices/system/cpu/online")
	if e != nil || string(cpus) != "0-7\n" {
		return nil, errors.New("fixed eight L1 CPUs required")
	}
	identity, e := processStart(pid)
	if e != nil {
		return nil, e
	}
	t = &creationCostTrace{diagnosticMode: mode, scope: scope, ordinaryELF: h, window: window, creates: make([]costCreateElapsed, 0, 5), target: prepareTrace{pid: pid, identity: identity}, formats: make(map[string]string)}
	defer func() {
		if err != nil {
			err = errors.Join(err, t.close(), t.emitABI(true))
		}
	}()
	if e = t.target.daemon(); e != nil {
		return t, e
	}
	var st unix.Statfs_t
	if e = unix.Statfs(prepareTraceRoot, &st); e != nil || st.Type == unix.TRACEFS_MAGIC {
		return t, errors.New("fresh unmounted owned L1 tracefs required")
	}
	tids, e := t.freeze()
	if e != nil {
		return t, e
	}
	t.initialTasks = tids
	t.initialAnchors, e = costAnchors(pid)
	if e != nil {
		return t, e
	}
	if e = unix.Mount("tracefs", prepareTraceRoot, "tracefs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); e != nil {
		return t, e
	}
	t.mounted = true
	b, e := costRead(prepareTraceRoot+"/uprobe_events", 4096)
	if e != nil || len(bytes.TrimSpace(b)) != 0 {
		return t, errors.New("fresh uprobe registry required; no probes are registered")
	}
	if e = os.Mkdir(costTraceInstance, 0700); e != nil {
		return t, e
	}
	t.instance = true
	for _, p := range [][2]string{{"tracing_on", "0"}, {"current_tracer", "nop"}, {"buffer_size_kb", "64"}, {"trace_clock", "mono"}, {"options/context-info", "1"}, {"options/irq-info", "1"}, {"options/latency-format", "0"}, {"options/event-fork", "1"}, {"set_event_pid", strings.Join(tids, " ")}} {
		if e = traceWrite(costTraceInstance+"/"+p[0], p[1]); e != nil {
			return t, e
		}
	}
	for _, name := range costTraceEvents {
		b, e := costRead(costTraceInstance+"/events/"+name+"/format", 8192)
		if e != nil {
			return t, e
		}
		t.formats[name] = string(b)
		if !bytes.Contains(b, []byte("name: "+strings.Split(name, "/")[1]+"\n")) {
			return t, errors.New("unexpected fixed syscall event format")
		}
		if strings.HasSuffix(name, "sys_enter_sync_file_range") {
			if e = costRangeFormat(b); e != nil {
				return t, e
			}
		}

		if e = traceWrite(costTraceInstance+"/events/"+name+"/enable", "1"); e != nil {
			return t, e
		}
		t.enabled = append(t.enabled, name)
	}
	if e = t.emitABI(false); e != nil {
		return t, e
	}
	if e = traceWrite(costTraceInstance+"/tracing_on", "1"); e != nil {
		return t, e
	}
	if e = t.resume(); e != nil {
		return t, e
	}
	return t, nil
}
func costPackets(scope string, payload []byte) ([][]byte, error) {
	if scope != "checkpoint" && scope != "cold" {
		return nil, errors.New("fixed cost scope required")
	}
	if len(payload) == 0 || len(payload) > 1<<20 {
		return nil, errors.New("cost payload bound")
	}
	sum := sha256.Sum256(payload)
	h := hex.EncodeToString(sum[:])
	n := (len(payload) + 2047) / 2048
	var rows [][]byte
	for i := 0; i < n; i++ {
		end := min(len(payload), (i+1)*2048)
		row, e := json.Marshal(map[string]any{"scope": scope, "index": i, "chunks": n, "sha256": h, "bytes": len(payload), "data": base64.StdEncoding.EncodeToString(payload[i*2048 : end])})
		if e != nil || len(row) > 4096 {
			return nil, errors.New("cost console framing bound")
		}
		rows = append(rows, row)
	}
	return rows, nil
}
func (t *creationCostTrace) collect(scope string) (err error) {
	if t == nil || t.closed || !t.instance || !t.abiQualified {
		return errors.New("active cost observation required")
	}
	defer func() { err = errors.Join(err, t.close()) }()
	if e := t.validateCreates(scope); e != nil {
		return e
	}
	if _, e := t.freeze(); e != nil {
		return e
	}
	if e := traceWrite(costTraceInstance+"/tracing_on", "0"); e != nil {
		return e
	}
	raw, e := costRead(costTraceInstance+"/trace", costTraceMax)
	if e != nil {
		return e
	}
	if len(raw) == 0 {
		return errors.New("empty cost trace")
	}
	stats := make(map[string]string)
	for cpu := 0; cpu < 8; cpu++ {
		b, e := costRead(filepath.Join(costTraceInstance, "per_cpu", fmt.Sprintf("cpu%d", cpu), "stats"), 8192)
		if e != nil {
			return e
		}
		if e = validatePrepareTraceStats(b); e != nil {
			return e
		}
		stats[strconv.Itoa(cpu)] = string(b)
	}
	anchors, e := costAnchors(t.target.pid)
	if e != nil {
		return e
	}
	filter, e := costRead(costTraceInstance+"/set_event_pid", 8192)
	if e != nil {
		return e
	}
	packet := map[string]any{"schema": 3, "scope": scope, "ordinary_elf_sha256": t.ordinaryELF, "asset_writeback_window_bytes": t.window, "http_create_elapsed": t.creates, "target_pid": t.target.pid, "target_start_ticks": t.target.identity, "initial_stopped_threads": t.initialTasks, "event_pid_after": string(filter), "raw": base64.StdEncoding.EncodeToString(raw), "runtime_anchor_before": t.initialAnchors, "runtime_anchor_after": anchors, "cpu_stats": stats, "event_formats": t.formats, "setup_and_collection_outside_workload": true, "subtree_events_require_time_ordered_task_lineage_before_daemon_timings": true, "no_user_memory_read_or_dynamic_probe_or_L0_trace": true, "not_production_or_speedup_proof": true}
	b, e := json.Marshal(packet)
	if e != nil {
		return e
	}
	// Fixed synthetic maximum-size transport probe; no timing/trace bytes removed.
	b, e = costNormalPayload(t.diagnosticMode, b)
	if e != nil {
		return e
	}
	rows, e := costPackets(scope, b)
	if e != nil {
		return e
	}
	// Resume the exact daemon and remove all owned tracing state BEFORE private
	// console output, which cannot flush the workload's /srv filesystem.
	if e = t.close(); e != nil {
		return e
	}
	for _, row := range rows {
		if _, e = fmt.Fprintf(os.Stderr, "XANDBOX_CREATION_COST_PRIVATE %s\n", row); e != nil {
			return e
		}
	}
	t.published = true
	return nil
}
func (t *creationCostTrace) close() error {
	if t == nil || t.closed {
		return nil
	}
	if e := requireNode(); e != nil {
		return e
	}
	var errs []error
	if t.instance {
		errs = append(errs, traceWrite(costTraceInstance+"/tracing_on", "0"))
		for _, name := range t.enabled {
			errs = append(errs, traceWrite(costTraceInstance+"/events/"+name+"/enable", "0"))
		}
		if e := os.Remove(costTraceInstance); e != nil {
			errs = append(errs, e)
		} else {
			t.instance = false
		}
	}
	if t.mounted {
		b, e := costRead(prepareTraceRoot+"/uprobe_events", 4096)
		errs = append(errs, e)
		if e == nil && len(bytes.TrimSpace(b)) != 0 {
			errs = append(errs, errors.New("unexpected owned L1 probe registry mutation"))
		}
		if e := unix.Unmount(prepareTraceRoot, 0); e != nil {
			errs = append(errs, e)
		} else {
			t.mounted = false
		}
	}
	errs = append(errs, t.resume())
	result := errors.Join(errs...)
	if result == nil {
		t.closed = true
	}
	return result
}

// The daemon is stopped while these exact proc-FD metadata are read. Read no
// input buffers and do not reopen or mutate any target descriptor.
func costAnchors(pid int) (map[string]map[string]uint64, error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	var root unix.Stat_t
	if e := unix.Stat("/srv/r", &root); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if e != nil {
		return nil, e
	}
	if len(entries) > 1024 {
		return nil, errors.New("fixed daemon FD bound")
	}
	out := make(map[string]map[string]uint64)
	for _, entry := range entries {
		name := fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())
		target, e := os.Readlink(name)
		if e != nil {
			return nil, e
		}
		if target != "/srv/r" {
			continue
		}
		fd, e := strconv.ParseUint(entry.Name(), 10, 32)
		if e != nil {
			return nil, e
		}
		var st unix.Stat_t
		if e = unix.Stat(name, &st); e != nil {
			return nil, e
		}
		if st.Dev != root.Dev || st.Ino != root.Ino || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, errors.New("runtime anchor inode mismatch")
		}
		raw, e := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, entry.Name()))
		if e != nil {
			return nil, e
		}
		mountID := uint64(0)
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && f[0] == "mnt_id:" {
				if len(f) != 2 || mountID != 0 {
					return nil, errors.New("ambiguous mount ID")
				}
				mountID, e = strconv.ParseUint(f[1], 10, 64)
				if e != nil || mountID == 0 {
					return nil, errors.New("invalid mount ID")
				}
			}
		}
		if mountID == 0 {
			return nil, errors.New("missing mount ID")
		}
		out[entry.Name()] = map[string]uint64{"fd": fd, "device": st.Dev, "inode": st.Ino, "mount_id": mountID}
	}
	if len(out) == 0 {
		return nil, errors.New("exact live runtime anchor required")
	}
	return out, nil
}
