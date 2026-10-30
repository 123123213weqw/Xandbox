//go:build linux && xandbox_host_fixture

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const costOrdinaryB = "596a7db7480d57f904fa35240cddbc0bc8eb9f2ff8c4059f9335f83d25b71f69"

type costCreateElapsed struct {
	Ordinal   int    `json:"ordinal"`
	Phase     string `json:"phase"`
	ElapsedNS int64  `json:"elapsed_ns"`
	Success   bool   `json:"success"`
}

func costWindowForELF(h string) (int64, error) {
	switch h {
	case prepareTraceELFSHA:
		return 8 << 20, nil
	case costOrdinaryB:
		return 1 << 20, nil
	default:
		return 0, errors.New("only fixed A/B ordinary ELFs allowed")
	}
}
func costRangeFormat(b []byte) error {
	text := string(b)
	if !strings.Contains(text, "name: sys_enter_sync_file_range\n") {
		return errors.New("fixed range event name")
	}
	allowed := map[string]bool{"common_type": true, "common_flags": true, "common_preempt_count": true, "common_pid": true, "__syscall_nr": true, "fd": true, "offset": true, "nbytes": true, "flags": true}
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "field:") {
			continue
		}
		declaration, _, ok := strings.Cut(strings.TrimPrefix(line, "field:"), ";")
		fields := strings.Fields(declaration)
		if !ok || len(fields) < 2 || !allowed[fields[len(fields)-1]] || seen[fields[len(fields)-1]] {
			return errors.New("unknown or duplicate fixed range event field")
		}
		seen[fields[len(fields)-1]] = true
	}
	for _, v := range []struct {
		typ, name      string
		offset, signed int
	}{{"int", "fd", 16, 0}, {"loff_t", "offset", 24, 0}, {"loff_t", "nbytes", 32, 0}, {"unsigned int", "flags", 40, 0}} {
		pat := fmt.Sprintf(`(?m)^\s*field:%s %s;\s+offset:%d;\s+size:8;\s+signed:%d;\s*$`, regexp.QuoteMeta(v.typ), v.name, v.offset, v.signed)
		if len(regexp.MustCompile(pat).FindAllString(text, -1)) != 1 {
			return errors.New("fixed range event ABI fields")
		}
	}
	return nil
}
func (t *creationCostTrace) createLimit() int {
	if t.scope == "checkpoint" {
		return 5
	}
	if t.scope == "cold" {
		return 1
	}
	return 0
}
func (t *creationCostTrace) beginCreate() error {
	if t == nil || t.createLimit() == 0 || t.createInFlight || len(t.creates) >= t.createLimit() {
		return errors.New("fixed sequential create observation bound")
	}
	t.createInFlight = true
	return nil
}
func (t *creationCostTrace) finishCreate(elapsed time.Duration, success bool) error {
	if t == nil || !t.createInFlight || elapsed <= 0 || elapsed > 900*time.Second {
		return errors.New("invalid create observation completion")
	}
	phase := "initial"
	if t.scope == "cold" {
		phase = "cold-fresh"
	} else if len(t.creates) == 4 {
		phase = "checkpoint-fresh"
	}
	t.creates = append(t.creates, costCreateElapsed{Ordinal: len(t.creates), Phase: phase, ElapsedNS: int64(elapsed), Success: success})
	t.createInFlight = false
	return nil
}
func (t *creationCostTrace) validateCreates(scope string) error {
	if t == nil || scope != t.scope || t.createLimit() == 0 || t.createInFlight || len(t.creates) != t.createLimit() {
		return errors.New("incomplete fixed create elapsed inventory")
	}
	for _, r := range t.creates {
		if !r.Success || r.ElapsedNS <= 0 {
			return errors.New("failed create sample retained, no valid comparison")
		}
	}
	return nil
}
func (t *creationCostTrace) finish() error {
	if t == nil {
		return nil
	}
	err := t.close()
	if !t.published && !t.abortPublished {
		t.abortPublished = true
		b, e := json.Marshal(map[string]any{"schema": 1, "scope": t.scope, "ordinary_elf_sha256": t.ordinaryELF, "http_create_elapsed": t.creates, "create_in_flight": t.createInFlight, "valid_comparison": false})
		if e == nil && len(b) <= 4096 {
			_, e = fmt.Fprintf(os.Stderr, "XANDBOX_CREATION_COST_FAILED_CREATES_PRIVATE %s\n", b)
		}
		err = errors.Join(err, e)
	}
	return err
}

// Fixed kernel syscall arguments use unsigned-long storage slots, independent
// of their C typedef signedness. Rejected actual formats must not disappear.
func (t *creationCostTrace) abiRows(rejected bool) ([][]byte, error) {
	if t == nil {
		return nil, errors.New("owned ABI state required")
	}
	kind := "qualified_before_trace_and_create"
	if rejected {
		kind = "setup_rejected_no_valid_measurement"
	} else if len(t.formats) != len(costTraceEvents) {
		return nil, errors.New("all fixed event formats required before create")
	}
	b, e := json.Marshal(map[string]any{"schema": 1, "kind": kind, "scope": t.scope, "ordinary_elf_sha256": t.ordinaryELF, "asset_writeback_window_bytes": t.window, "event_formats": t.formats, "tracing_off_before_measured_create": true})
	if e != nil {
		return nil, e
	}
	return costPackets(t.scope, b)
}
func (t *creationCostTrace) emitABI(rejected bool) error {
	rows, e := t.abiRows(rejected)
	if e != nil {
		return e
	}
	prefix := "XANDBOX_CREATION_COST_ABI_PRIVATE"
	if rejected {
		prefix = "XANDBOX_CREATION_COST_SETUP_FAILURE_PRIVATE"
	}
	for _, row := range rows {
		if _, e = fmt.Fprintf(os.Stderr, "%s %s\n", prefix, row); e != nil {
			return e
		}
	}
	if !rejected {
		t.abiQualified = true
	}
	return nil
}
