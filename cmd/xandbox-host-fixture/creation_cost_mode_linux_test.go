//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestCreationCostDefaultOffDoesNotCallIdentityTraceOrSignal(t *testing.T) {
	called := false
	p, e := withCreationCostMode(creationCostOff, func() (*creationCostTrace, error) { called = true; panic("OFF must not inspect or signal") })
	if e != nil || p != nil || called {
		t.Fatal("disabled diagnostic performed work")
	}
	p, e = startCreationCostTraceForMode(creationCostOff, -1, "not-even-a-scope")
	if e != nil || p != nil {
		t.Fatal("OFF reached scope/PID/node/ELF validation")
	}
	if configuredCreationCostMode != creationCostOff {
		t.Fatal("diagnostics enabled by default")
	}
}
func TestCreationCostClosedStartupModesNeverApplyToOtherFixtures(t *testing.T) {
	for _, mode := range []string{"observe", "maximum"} {
		selected, e := parseCreationCostMode(mode, "node-budget", "", 0)
		if e != nil || string(selected) != mode {
			t.Fatal("explicit healthy mode refused")
		}
		for _, target := range []string{"launch", "qemu-child", "node-load", "node-snapshot", "node-budget-daemon", ""} {
			if _, e := parseCreationCostMode(mode, target, "", 0); e == nil {
				t.Fatal("other mode accepted")
			}
		}
		if _, e := parseCreationCostMode(mode, "node-budget", "config", 0); e == nil {
			t.Fatal("unexpected config")
		}
		if _, e := parseCreationCostMode(mode, "node-budget", "", 1); e == nil {
			t.Fatal("positional argument")
		}
	}
	for _, bad := range []string{"", "unknown", "maximum; exit", "Observe"} {
		if _, e := parseCreationCostMode(bad, "node-budget", "", 0); e == nil {
			t.Fatal("unknown selector")
		}
	}
	if selected, e := parseCreationCostMode("off", "launch", "existing-config", 3); e != nil || selected != creationCostOff {
		t.Fatal("OFF changed legacy mode validation")
	}
}
func TestCreationCostEnabledGatePreservesReturnAndErrorIdentity(t *testing.T) {
	marker := errors.New("synthetic original error")
	original := &creationCostTrace{}
	for _, mode := range []creationCostMode{creationCostObserve, creationCostMaximum} {
		count := 0
		p, e := withCreationCostMode(mode, func() (*creationCostTrace, error) { count++; return original, marker })
		if count != 1 || p != original || e != marker {
			t.Fatal("enabled dispatch changed identity")
		}
	}
	called := false
	if _, e := withCreationCostMode("bad", func() (*creationCostTrace, error) { called = true; return nil, nil }); e == nil || called {
		t.Fatal("unknown mode performed work")
	}
}
func TestCreationCostObserveKeepsUnpaddedActualPayload(t *testing.T) {
	original := []byte(`{"schema":3}`)
	out, e := costNormalPayload(creationCostObserve, original)
	if e != nil || !bytes.Equal(out, original) || len(out) != len(original) {
		t.Fatal("observe padded or changed bytes")
	}
	padded, e := costNormalPayload(creationCostMaximum, original)
	if e != nil || len(padded) != 1<<20 || !bytes.Equal(padded[:len(original)], original) {
		t.Fatal("maximum did not use explicit synthetic prefix preserving shape")
	}
	if _, e := costNormalPayload(creationCostOff, original); e == nil {
		t.Fatal("inactive collection accepted")
	}
}
func TestCreationCostNilCollectionAndFinishKeepOriginalFailure(t *testing.T) {
	marker := errors.New("synthetic failure")
	current := error(marker)
	if e := collectCreationCostIfEnabled(nil, "not-a-scope"); e != nil {
		t.Fatal("OFF collection performed work")
	}
	mergeCreationCostFinish(nil, &current)
	if current != marker {
		t.Fatal("OFF wrapped original failure")
	}
	p := &creationCostTrace{closed: true, published: true}
	mergeCreationCostFinish(p, &current)
	if current != marker {
		t.Fatal("successful finish wrapped original failure")
	}
}
func TestCreationCostRangeABIUnknownAndDuplicateFieldsFailEarly(t *testing.T) {
	valid := "name: sys_enter_sync_file_range\nfield:int fd; offset:16; size:8; signed:0;\nfield:loff_t offset; offset:24; size:8; signed:0;\nfield:loff_t nbytes; offset:32; size:8; signed:0;\nfield:unsigned int flags; offset:40; size:8; signed:0;\n"
	if costRangeFormat([]byte(valid)) != nil {
		t.Fatal("valid synthetic ABI")
	}
	for _, extra := range []string{"field:int surprise; offset:48; size:8; signed:0;\n", "field:int fd; offset:16; size:8; signed:0;\n", "field:;\n"} {
		if costRangeFormat([]byte(valid+extra)) == nil {
			t.Fatal("unknown/duplicate/malformed field accepted")
		}
	}
}
