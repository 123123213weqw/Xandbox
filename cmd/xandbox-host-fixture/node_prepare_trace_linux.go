//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: fixed instruction-entry uprobes in our isolated L1. This is a
// calibration of the frozen ordinary daemon, not a generic tracer, production
// telemetry, cancellation test, or a scheduler/latency benchmark. No uretprobe,
// return-address rewrite, stack access, user-buffer read, or L0 tracing occurs.
import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"golang.org/x/sys/unix"
)

const prepareTraceELFSHA = "4ddd4bea5ee252fd4b52a7132bfbab9723d76bbaa1941d4c341ce770e0802218"
const prepareTraceRoot = "/sys/kernel/tracing"
const prepareTraceInstance = prepareTraceRoot + "/instances/xandbox_prepare_calibration"
const prepareTraceGroup = "xandbox_prepare_calibration"
const prepareTraceMaxBytes = 1 << 20
const prepareTraceMaxEvents = 64

type prepareProbe struct {
	name, symbol     string
	address          uint64
	opcode, register string
}

// Addresses are instruction boundaries from go1.27.3 linux/amd64 objdump of
// prepareTraceELFSHA. Verify the WHOLE ELF, symbol containment and exact bytes
// before mounting tracefs or registering anything. These are ordinary entry
// probes even at a post-CALL instruction; they are never return probes.
// Release is inlined in Prepare.deferwrap1, not the out-of-line release symbol.
// Both pre-receive release probes read CX (the gate); other points read AX.
// node_ok is the checked success path before return/defer bookkeeping, NOT
// an actual function return. Its AX is not interpreted as a result or identity.
func prepareProbes() []prepareProbe {
	const prefix = "github.com/123123213weqw/Xandbox/internal/firecracker."
	return []prepareProbe{
		{"enter", prefix + "(*prepareGate).acquire", 0x74c152, "4889842480000000", "ax"},
		{"selected", prefix + "(*prepareGate).acquire", 0x74c1c5, "4885c0", "ax"},
		{"ok", prefix + "(*prepareGate).acquire", 0x74c215, "31c0", "ax"},
		{"cancel", prefix + "(*prepareGate).acquire", 0x74c235, "4883c470", "ax"},
		{"race_release", prefix + "(*prepareGate).acquire", 0x74c205, "488b442438", "ax"},
		{"node_ok", prefix + "(*nodeEnvelope).acquirePrepare", 0x749b01, "440f117c2430", "ax"},
		{"node_reject_release", prefix + "(*nodeEnvelope).acquirePrepare", 0x749aac, "488b01", "cx"},
		{"release", prefix + "(*driver).Prepare.deferwrap1", 0x756012, "488b01", "cx"},
		{"released", prefix + "(*driver).Prepare.deferwrap1", 0x75601c, "4883c410", "ax"},
	}
}

func prepareProbeOffsets(f *elf.File, raw io.ReaderAt) ([]uint64, error) {
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 || f.Type != elf.ET_EXEC || f.Data != elf.ELFDATA2LSB {
		return nil, errors.New("fixed amd64 static executable required")
	}
	syms, e := f.Symbols()
	if e != nil {
		return nil, e
	}
	var offsets []uint64
	for _, p := range prepareProbes() {
		valid := false
		for _, s := range syms {
			if s.Name == p.symbol && s.Size > 0 && p.address >= s.Value && p.address-s.Value < s.Size {
				valid = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("fixed probe symbol mismatch: %s", p.name)
		}
		code, e := hex.DecodeString(p.opcode)
		if e != nil {
			return nil, e
		}
		found := false
		for _, seg := range f.Progs {
			if seg.Type != elf.PT_LOAD || seg.Flags&elf.PF_X == 0 || p.address < seg.Vaddr || p.address-seg.Vaddr > seg.Filesz || uint64(len(code)) > seg.Filesz-(p.address-seg.Vaddr) {
				continue
			}
			offset := seg.Off + p.address - seg.Vaddr
			got := make([]byte, len(code))
			if _, e = raw.ReadAt(got, int64(offset)); e != nil || !bytes.Equal(got, code) {
				return nil, fmt.Errorf("fixed instruction mismatch: %s", p.name)
			}
			offsets = append(offsets, offset)
			found = true
			break
		}
		if !found {
			return nil, errors.New("probe outside file-backed executable segment")
		}
	}
	return offsets, nil
}

type prepareTrace struct {
	pid        int
	identity   string
	registered []string
	mounted    bool
	instance   bool
}

func traceWrite(name, value string) error { return os.WriteFile(name, []byte(value+"\n"), 0) }
func traceProbeCommand(value string) error {
	// O_TRUNC on uprobe_events can clear existing probes. Append exactly one
	// fixed command, including during partial-start cleanup.
	f, e := os.OpenFile(prepareTraceRoot+"/uprobe_events", os.O_WRONLY|os.O_APPEND, 0)
	if e != nil {
		return e
	}
	_, e = f.WriteString(value + "\n")
	return errors.Join(e, f.Close())
}
func traceRead(name string) ([]byte, error) {
	f, e := os.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, prepareTraceMaxBytes+1))
	if len(b) > prepareTraceMaxBytes {
		return nil, errors.New("fixed trace read bound exceeded")
	}
	return b, e
}

func (t *prepareTrace) daemon() error {
	if e := requireNode(); e != nil {
		return e
	}
	id, e := processStart(t.pid)
	if e != nil || id != t.identity {
		return errors.New("trace target incarnation changed")
	}
	a, e := os.Stat(fmt.Sprintf("/proc/%d/exe", t.pid))
	if e != nil {
		return e
	}
	b, e := os.Stat("/srv/assets/sandboxd")
	if e != nil || !os.SameFile(a, b) {
		return errors.New("trace target executable inode changed")
	}
	cg, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", t.pid))
	if e != nil || string(cg) != "0::/xandbox/control\n" {
		return errors.New("trace target outside exact node control")
	}
	return nil
}

func startPrepareTrace(pid int) (t *prepareTrace, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if _, e := fixedNodeSnapshotConfig(); e != nil {
		return nil, e
	}
	h, e := fileHash("/srv/assets/sandboxd")
	if e != nil || h != prepareTraceELFSHA {
		return nil, errors.New("trace requires exact qualified ordinary daemon ELF")
	}
	f, e := os.Open("/srv/assets/sandboxd")
	if e != nil {
		return nil, e
	}
	defer f.Close()
	ef, e := elf.NewFile(f)
	if e != nil {
		return nil, e
	}
	defer ef.Close()
	offsets, e := prepareProbeOffsets(ef, f)
	if e != nil {
		return nil, e
	}
	id, e := processStart(pid)
	if e != nil {
		return nil, e
	}
	t = &prepareTrace{pid: pid, identity: id}
	defer func() {
		if err != nil {
			err = errors.Join(err, t.close())
		}
	}()
	if e = t.daemon(); e != nil {
		return t, e
	}
	var u unix.Utsname
	if e = unix.Uname(&u); e != nil || unix.ByteSliceToString(u.Release[:]) != "6.8.0-136-generic" {
		return t, errors.New("fixed isolated L1 tracing kernel required")
	}
	var before unix.Statfs_t
	if e = unix.Statfs(prepareTraceRoot, &before); e != nil || before.Type == unix.TRACEFS_MAGIC {
		return t, errors.New("tracefs must not already be mounted")
	}
	if e = unix.Mount("tracefs", prepareTraceRoot, "tracefs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); e != nil {
		return t, e // Never adopt an already mounted tracefs or unknown probes.
	}
	t.mounted = true
	prior, e := traceRead(prepareTraceRoot + "/uprobe_events")
	if e != nil || len(bytes.TrimSpace(prior)) != 0 {
		return t, errors.New("fresh owned L1 uprobe registry required")
	}
	if e = os.Mkdir(prepareTraceInstance, 0700); e != nil {
		return t, e
	}
	t.instance = true
	for _, setting := range [][2]string{{"tracing_on", "0"}, {"current_tracer", "nop"}, {"buffer_size_kb", "64"}, {"trace_clock", "mono"}, {"options/context-info", "1"}, {"options/irq-info", "1"}, {"options/latency-format", "0"}, {"options/event-fork", "1"}, {"set_event_pid", strconv.Itoa(pid)}} {
		if e = traceWrite(prepareTraceInstance+"/"+setting[0], setting[1]); e != nil {
			return t, e
		}
	}
	tasks, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if e != nil || len(tasks) == 0 || len(tasks) > 128 {
		return t, errors.New("bounded live daemon threads required")
	}
	var tids []string
	for _, task := range tasks {
		if _, e = strconv.ParseUint(task.Name(), 10, 32); e != nil {
			return t, e
		}
		tids = append(tids, task.Name())
	}
	if e = traceWrite(prepareTraceInstance+"/set_event_pid", strings.Join(tids, " ")); e != nil {
		return t, e
	}
	for i, p := range prepareProbes() {
		definition := fmt.Sprintf("p:%s/xbg_%s /srv/assets/sandboxd:0x%x g=%%r14:x64 value=%%%s:x64", prepareTraceGroup, p.name, offsets[i], p.register)
		if e = traceProbeCommand(definition); e != nil {
			return t, fmt.Errorf("register fixed %s: %w", p.name, e)
		}
		t.registered = append(t.registered, p.name)
		if e = traceWrite(prepareTraceInstance+"/events/"+prepareTraceGroup+"/xbg_"+p.name+"/enable", "1"); e != nil {
			return t, e
		}
	}
	if e = traceWrite(prepareTraceInstance+"/tracing_on", "1"); e != nil {
		return t, e
	}
	return t, nil
}

func (t *prepareTrace) close() error {
	if e := requireNode(); e != nil {
		return e
	}
	var errs []error
	if t.instance {
		errs = append(errs, traceWrite(prepareTraceInstance+"/tracing_on", "0"))
		for _, name := range t.registered {
			errs = append(errs, traceWrite(prepareTraceInstance+"/events/"+prepareTraceGroup+"/xbg_"+name+"/enable", "0"))
		}
	}
	for _, name := range t.registered {
		errs = append(errs, traceProbeCommand("-:"+prepareTraceGroup+"/xbg_"+name))
	}
	if t.instance {
		errs = append(errs, os.Remove(prepareTraceInstance))
	}
	if t.mounted {
		b, e := traceRead(prepareTraceRoot + "/uprobe_events")
		errs = append(errs, e)
		if e == nil && len(bytes.TrimSpace(b)) != 0 {
			errs = append(errs, errors.New("owned trace registry not empty after unregister"))
		}
		errs = append(errs, unix.Unmount(prepareTraceRoot, 0))
	}
	return errors.Join(errs...)
}

type prepareTraceEvent struct {
	tid, cpu int
	nanos    uint64
	name     string
	g, ax    uint64
}

var prepareTraceLine = regexp.MustCompile(`^\s*.+-([0-9]+)\s+\[([0-9]+)\]\s+\S+\s+([0-9]+)\.([0-9]{6}):\s+xbg_([a-z_]+):\s+\((0x[0-9a-f]+)\)\s+g=(0x[0-9a-f]+)\s+value=(0x[0-9a-f]+)\s*$`)

func parsePrepareTrace(raw []byte) ([]prepareTraceEvent, error) {
	if len(raw) == 0 || len(raw) > prepareTraceMaxBytes {
		return nil, errors.New("bounded nonempty trace required")
	}
	var events []prepareTraceEvent
	known := make(map[string]uint64)
	for _, p := range prepareProbes() {
		known[p.name] = p.address
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		m := prepareTraceLine.FindStringSubmatch(line)
		if m == nil || known[m[5]] == 0 || len(events) >= prepareTraceMaxEvents {
			return nil, errors.New("unknown, malformed or excess fixed trace event")
		}
		tid, e := strconv.ParseUint(m[1], 10, 32)
		if e != nil || tid == 0 {
			return nil, errors.New("invalid trace tid")
		}
		cpu, e := strconv.ParseUint(m[2], 10, 16)
		if e != nil || cpu >= 8 {
			return nil, errors.New("trace outside fixed8 CPUs")
		}
		secs, e := strconv.ParseUint(m[3], 10, 32)
		if e != nil {
			return nil, e
		}
		micros, _ := strconv.ParseUint(m[4], 10, 32)
		ip, ie := strconv.ParseUint(m[6][2:], 16, 64)
		g, ge := strconv.ParseUint(m[7][2:], 16, 64)
		ax, ae := strconv.ParseUint(m[8][2:], 16, 64)
		if ie != nil || ip != known[m[5]] || ge != nil || ae != nil || g == 0 {
			return nil, errors.New("missing fixed ABI register value")
		}
		ev := prepareTraceEvent{int(tid), int(cpu), secs*1_000_000_000 + micros*1000, m[5], g, ax}
		if len(events) > 0 && ev.nanos < events[len(events)-1].nanos {
			return nil, errors.New("trace clock order regressed")
		}
		events = append(events, ev)
	}
	return events, nil
}

func validatePrepareCalibration(events []prepareTraceEvent) (bool, error) {
	// Each live original create has a different g pointer. Thread IDs can change
	// across a blocked Go select; do not correlate a goroutine by OS thread ID.
	state := make(map[uint64]int)
	var gate uint64
	held, completed, entered := 0, 0, 0
	contendedEntry := false
	for _, ev := range events {
		s := state[ev.g]
		switch ev.name {
		case "enter":
			if s != 0 || entered == 2 || ev.ax == 0 || (gate != 0 && gate != ev.ax) {
				return false, errors.New("duplicate/foreign calibration gate entry")
			}
			gate = ev.ax
			contendedEntry = contendedEntry || held == 1
			entered++
			state[ev.g] = 1
		case "selected":
			if s != 1 || ev.ax != 0 || held != 0 {
				return false, errors.New("unexpected select branch or overlapping held permits")
			}
			held++
			state[ev.g] = 2
		case "ok", "node_ok", "release", "released":
			want := map[string]int{"ok": 2, "node_ok": 3, "release": 4, "released": 5}[ev.name]
			if s != want {
				return false, errors.New("missing, reordered or duplicate permit transition")
			}
			if ev.name == "release" {
				if held != 1 || ev.ax != gate {
					return false, errors.New("release of wrong gate or no held permit")
				}
				held-- // pre-receive boundary, NOT the exact channel linearization.
			}
			if ev.name == "released" {
				completed++
			}
			state[ev.g] = s + 1
		default:
			return false, errors.New("calibration unexpected cancellation/node rejection path")
		}
	}
	if len(events) != 12 || entered != 2 || completed != 2 || held != 0 || len(state) != 2 || !contendedEntry {
		return false, fmt.Errorf("incomplete calibration events=%d entered=%d completed=%d held=%d goroutines=%d contended_entry=%t", len(events), entered, completed, held, len(state), contendedEntry)
	}
	return contendedEntry, nil
}

// A simultaneous HTTP barrier does not imply this order: both entry probes
// can run before either goroutine reaches its channel select.
func prepareFirstHeld(events []prepareTraceEvent) (bool, error) {
	want := []string{"enter", "selected", "ok", "node_ok"}
	if len(events) > len(want) {
		return false, errors.New("first preparation released before second dispatch")
	}
	for i, ev := range events {
		if ev.name != want[i] || ev.g != events[0].g || (ev.name == "selected" && ev.ax != 0) {
			return false, errors.New("unexpected first preparation trace prefix")
		}
	}
	return len(events) >= 2, nil
}

func normalizedPrepareTransitions(events []prepareTraceEvent) []map[string]any {
	ordinals := make(map[uint64]int)
	var out []map[string]any
	for _, ev := range events {
		if ordinals[ev.g] == 0 {
			ordinals[ev.g] = len(ordinals) + 1
		}
		// No raw pointers, TID, PID, CPU, absolute timestamps or tenant identity.
		out = append(out, map[string]any{"point": ev.name, "goroutine_index": ordinals[ev.g]})
	}
	return out
}

func validatePrepareTraceStats(raw []byte) error {
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		if name != "overrun" && name != "commit overrun" && name != "dropped events" {
			continue
		}
		if seen[name] || strings.TrimSpace(kv[1]) != "0" {
			return errors.New("trace buffer loss or invalid duplicate stats")
		}
		seen[name] = true
	}
	if len(seen) != 3 {
		return errors.New("missing trace loss counters")
	}
	return nil
}

func validatePrepareProfile(raw []byte, events []prepareTraceEvent) error {
	counts, seen := make(map[string]int), make(map[string]bool)
	for _, p := range prepareProbes() {
		counts["xbg_"+p.name] = 0
	}
	for _, ev := range events {
		counts["xbg_"+ev.name]++
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "/srv/assets/sandboxd" {
			return errors.New("unknown uprobe profile image/format")
		}
		want, known := counts[f[1]]
		n, e := strconv.Atoi(f[2])
		if !known || seen[f[1]] || e != nil || n != want {
			return errors.New("uprobe hit count differs from complete trace")
		}
		seen[f[1]] = true
	}
	if len(seen) != len(counts) {
		return errors.New("missing uprobe profile counters")
	}
	return nil
}

func (t *prepareTrace) collect(scope string) ([]prepareTraceEvent, error) {
	if scope != "calibration" && scope != "cancel" {
		return nil, errors.New("fixed trace scope required")
	}
	if e := t.daemon(); e != nil {
		return nil, e
	}
	if e := traceWrite(prepareTraceInstance+"/tracing_on", "0"); e != nil {
		return nil, e
	}
	raw, e := traceRead(prepareTraceInstance + "/trace")
	if e != nil {
		return nil, e
	}
	// Raw register values and per-thread identities stay root0600 INSIDE L1.
	log, e := os.OpenFile("/srv/fixture/node-prepare-"+scope+"-private.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	if _, e = log.Write(raw); e != nil {
		return nil, e
	}
	for cpu := 0; cpu < 8; cpu++ {
		stats, err := traceRead(filepath.Join(prepareTraceInstance, "per_cpu", fmt.Sprintf("cpu%d", cpu), "stats"))
		if err != nil {
			return nil, err
		}
		if _, err = fmt.Fprintf(log, "\n---cpu%d-stats---\n%s", cpu, stats); err != nil {
			return nil, err
		}
		if err = validatePrepareTraceStats(stats); err != nil {
			return nil, err
		}
	}
	if e = log.Sync(); e != nil {
		return nil, e
	}
	events, e := parsePrepareTrace(raw)
	if e != nil {
		return nil, e
	}
	profile, e := traceRead(prepareTraceRoot + "/uprobe_profile")
	if e != nil {
		return nil, e
	}
	if _, e = fmt.Fprintf(log, "\n---uprobe-profile---\n%s", profile); e != nil {
		return nil, e
	}
	if e = log.Sync(); e != nil {
		return nil, e
	}
	if e = validatePrepareProfile(profile, events); e != nil {
		return nil, e
	}
	for _, ev := range events {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", ev.tid))
		if err != nil || !strings.Contains("\n"+string(status), "\nTgid:\t"+strconv.Itoa(t.pid)+"\n") {
			return nil, errors.New("trace thread no longer verifiable in exact live daemon")
		}
	}
	if e = t.daemon(); e != nil {
		return nil, e
	}
	return events, nil
}

func (t *prepareTrace) finish() (map[string]any, error) {
	events, e := t.collect("calibration")
	if e != nil {
		return nil, e
	}
	contended, e := validatePrepareCalibration(events)
	if e != nil {
		return nil, fmt.Errorf("%w; normalized transitions=%v", e, normalizedPrepareTransitions(events))
	}
	return map[string]any{"normalized_transitions": normalizedPrepareTransitions(events), "first_selected_token_observed_before_second_dispatch": true, "calibration_only": true, "exact_ordinary_elf_sha256": prepareTraceELFSHA, "instruction_entry_probes": len(prepareProbes()), "event_count": len(events), "completed_preparations": 2, "second_actual_gate_entry_inside_first_held_interval": contended, "all_eight_cpu_loss_counters_zero": true, "live_daemon_incarnation_inode_control_and_event_tgid_checked": true, "entry_probe_only_no_uretprobe_or_user_memory_read": true, "queued_request_cancellation_and_cleanup_isolation_claim": false, "exact_channel_linearization_or_latency_slo_claim": false}, nil
}

func (n *node) nodePrepareCalibration(ctx context.Context, api *switchAPI) (a, b sandbox.Record, result map[string]any, err error) {
	if e := requireNode(); e != nil {
		return a, b, nil, e
	}
	if !n.nodeSnapshot || n.process == nil {
		return a, b, nil, errors.New("fixed live schema3 snapshot daemon required")
	}
	t, e := startPrepareTrace(n.process.Process.Pid)
	if e != nil {
		return a, b, nil, e
	}
	defer func() { err = errors.Join(err, t.close()) }()
	type reply struct {
		r    sandbox.Record
		boot string
		err  error
	}
	replies := make(chan reply, 2)
	requestCtx, cancelRequests := context.WithCancel(ctx)
	defer cancelRequests()
	create := func() {
		r, _, boot, err := n.nodeSnapshotGuest(requestCtx, api)
		replies <- reply{r, boot, err}
	}
	go create()
	observeCtx, cancelObserve := context.WithTimeout(ctx, 5*time.Second)
	e = waitNode(observeCtx, func() (bool, error) {
		raw, e := traceRead(prepareTraceInstance + "/trace")
		if e != nil {
			return false, e
		}
		events, e := parsePrepareTrace(raw)
		if e != nil {
			return false, e
		}
		return prepareFirstHeld(events)
	})
	cancelObserve()
	if e != nil {
		cancelRequests()
		x := <-replies
		return x.r, b, nil, errors.Join(e, x.err)
	}
	go create()
	x, y := <-replies, <-replies
	if e = errors.Join(x.err, y.err); e != nil {
		return x.r, y.r, nil, e
	}
	if x.r.Ref == y.r.Ref || x.boot == y.boot {
		return x.r, y.r, nil, errors.New("two calibration guests not independent")
	}
	result, e = t.finish()
	return x.r, y.r, result, e
}
