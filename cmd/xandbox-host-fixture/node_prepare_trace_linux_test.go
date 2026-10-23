//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"strings"
	"testing"
)

func calibrationEvents() []prepareTraceEvent {
	names := []string{"enter", "selected", "ok", "node_ok", "enter", "release", "selected", "released", "ok", "node_ok", "release", "released"}
	gs := []uint64{1, 1, 1, 1, 2, 1, 2, 1, 2, 2, 2, 2}
	var events []prepareTraceEvent
	for i, name := range names {
		ax := uint64(0)
		if name == "enter" || name == "release" {
			ax = 0x1234
		}
		events = append(events, prepareTraceEvent{tid: 20 + i%3, cpu: i % 8, nanos: uint64(i+1) * 1000, name: name, g: gs[i], ax: ax})
	}
	return events
}
func calibrationTrace(events []prepareTraceEvent) []byte {
	var b strings.Builder
	b.WriteString("# tracer: nop\n# entries-in-buffer/entries-written: 12/12 #P:8\n")
	for _, ev := range events {
		var ip uint64
		for _, p := range prepareProbes() {
			if p.name == ev.name {
				ip = p.address
			}
		}
		fmt.Fprintf(&b, "        sandboxd-%d [00%d] d... 1.%06d: xbg_%s: (0x%x) g=0x%x value=0x%x\n", ev.tid, ev.cpu, ev.nanos/1000, ev.name, ip, ev.g, ev.ax)
	}
	return []byte(b.String())
}
func TestPrepareCalibrationCorrelatesGoroutinesNotMigratingThreads(t *testing.T) {
	valid := calibrationEvents()
	parsed, e := parsePrepareTrace(calibrationTrace(valid))
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := validatePrepareCalibration(parsed); e != nil || !ok {
		t.Fatal("valid migrated two-create trace", e)
	}
	for i := range valid {
		for _, mode := range []string{"omit", "duplicate", "wrong-g", "unknown-path"} {
			t.Run(fmt.Sprintf("%d-%s", i, mode), func(t *testing.T) {
				events := append([]prepareTraceEvent(nil), valid...)
				switch mode {
				case "omit":
					events = append(events[:i], events[i+1:]...)
				case "duplicate":
					events = append(events, events[i])
				case "wrong-g":
					events[i].g = 99
				case "unknown-path":
					events[i].name = "cancel"
				}
				if _, e := validatePrepareCalibration(events); e == nil {
					t.Fatal("incomplete/foreign trace accepted")
				}
			})
		}
	}
	for _, change := range []func([]prepareTraceEvent){
		func(e []prepareTraceEvent) { e[4].ax++ },
		func(e []prepareTraceEvent) { e[1].ax = 1 },
		func(e []prepareTraceEvent) { e[5].ax++ },
		func(e []prepareTraceEvent) { e[6], e[5] = e[5], e[6] },
		func(e []prepareTraceEvent) { e[4], e[1] = e[1], e[4] },
	} {
		events := append([]prepareTraceEvent(nil), valid...)
		change(events)
		if _, e := validatePrepareCalibration(events); e == nil {
			t.Fatal("wrong gate, branch, overlap or noncontended entry accepted")
		}
	}
}
func TestPrepareTraceParserRejectsLossMalformedAndUnknownEvents(t *testing.T) {
	valid := calibrationTrace(calibrationEvents())
	for name, raw := range map[string][]byte{
		"empty": nil, "oversize": bytes.Repeat([]byte("x"), prepareTraceMaxBytes+1),
		"unknown":          bytes.Replace(valid, []byte("xbg_ok"), []byte("xbg_unknown"), 1),
		"bad-cpu":          bytes.Replace(valid, []byte("[000]"), []byte("[008]"), 1),
		"zero-g":           bytes.Replace(valid, []byte("g=0x1"), []byte("g=0x0"), 1),
		"missing-register": bytes.Replace(valid, []byte("ax=0x0"), []byte("ax=(fault)"), 1),
		"invalid-tid":      bytes.Replace(valid, []byte("sandboxd-20"), []byte("sandboxd-0"), 1),
		"backwards":        bytes.Replace(valid, []byte("1.000002"), []byte("0.000002"), 1),
		"excess":           bytes.Repeat([]byte("a-1 [000] d... 1.000001: xbg_enter: (0x73ff72) g=0x1 value=0x1\n"), prepareTraceMaxEvents+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := parsePrepareTrace(raw); e == nil {
				t.Fatal("unsafe trace accepted")
			}
		})
	}
	stats := []byte("entries: 12\noverrun: 0\ncommit overrun: 0\ndropped events: 0\n")
	if e := validatePrepareTraceStats(stats); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"overrun", "commit overrun", "dropped events"} {
		for _, raw := range [][]byte{bytes.Replace(stats, []byte(key+": 0"), []byte(key+": 1"), 1), bytes.Replace(stats, []byte(key+": 0\n"), nil, 1), append(append([]byte(nil), stats...), []byte(key+": 0\n")...)} {
			if validatePrepareTraceStats(raw) == nil {
				t.Fatal("lost/missing/duplicate loss counter accepted")
			}
		}
	}
}
func TestPrepareProbeProfileMustAccountForEveryInstructionHit(t *testing.T) {
	events := calibrationEvents()
	var b strings.Builder
	for _, p := range prepareProbes() {
		n := 0
		for _, ev := range events {
			if ev.name == p.name {
				n++
			}
		}
		fmt.Fprintf(&b, "/srv/assets/sandboxd xbg_%s %d\n", p.name, n)
	}
	raw := []byte(b.String())
	if e := validatePrepareProfile(raw, events); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{nil, bytes.ReplaceAll(raw, []byte("sandboxd"), []byte("other")), bytes.Replace(raw, []byte(" 2\n"), []byte(" 3\n"), 1), append(append([]byte(nil), raw...), raw...), bytes.Replace(raw, []byte("xbg_cancel"), []byte("xbg_unknown"), 1)} {
		if validatePrepareProfile(bad, events) == nil {
			t.Fatal("partial/foreign profile accepted")
		}
	}
}
func TestPrepareTraceFixedELFAndL1Only(t *testing.T) {
	for _, f := range []*elf.File{{}, {FileHeader: elf.FileHeader{Class: elf.ELFCLASS64, Data: elf.ELFDATA2LSB, Type: elf.ET_EXEC, Machine: elf.EM_X86_64}}} {
		if _, e := prepareProbeOffsets(f, bytes.NewReader(nil)); e == nil {
			t.Fatal("unqualified ELF/symbols accepted")
		}
	}
	if len(prepareProbes()) != 9 || len(prepareTraceELFSHA) != 64 {
		t.Fatal("fixed plan drift")
	}
	if _, e := startPrepareTrace(1); e == nil {
		t.Fatal("tracing escaped L1")
	}
	target := &prepareTrace{}
	if target.daemon() == nil || target.close() == nil {
		t.Fatal("target/cleanup escaped L1")
	}
	n := &node{}
	if _, _, _, e := n.nodePrepareCalibration(context.Background(), nil); e == nil {
		t.Fatal("calibration escaped L1")
	}
}
