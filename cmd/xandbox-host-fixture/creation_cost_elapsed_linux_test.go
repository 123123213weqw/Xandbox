//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCreationCostOnlyTwoFixedELFs(t *testing.T) {
	for _, h := range []string{prepareTraceELFSHA, costOrdinaryB} {
		if _, e := costWindowForELF(h); e != nil {
			t.Fatal(e)
		}
	}
	for _, h := range []string{"", strings.Repeat("0", 64), prepareTraceELFSHA + "x"} {
		if _, e := costWindowForELF(h); e == nil {
			t.Fatal("unknown program")
		}
	}
}
func TestCreationCostElapsedBoundOrderAndFailuresRetained(t *testing.T) {
	for _, scope := range []string{"checkpoint", "cold"} {
		p := &creationCostTrace{scope: scope}
		n := p.createLimit()
		for i := 0; i < n; i++ {
			if e := p.beginCreate(); e != nil {
				t.Fatal(e)
			}
			if e := p.beginCreate(); e == nil {
				t.Fatal("nested create accepted")
			}
			if e := p.finishCreate(time.Millisecond, true); e != nil {
				t.Fatal(e)
			}
		}
		if e := p.validateCreates(scope); e != nil {
			t.Fatal(e)
		}
		if e := p.beginCreate(); e == nil {
			t.Fatal("extra create")
		}
		if e := p.finishCreate(time.Millisecond, true); e == nil {
			t.Fatal("unsolicited completion")
		}
		if scope == "checkpoint" && p.creates[4].Phase != "checkpoint-fresh" {
			t.Fatal("wrong fifth phase")
		}
		if scope == "cold" && p.creates[0].Phase != "cold-fresh" {
			t.Fatal("wrong cold phase")
		}
	}
	p := &creationCostTrace{scope: "cold"}
	if e := p.beginCreate(); e != nil {
		t.Fatal(e)
	}
	if e := p.finishCreate(time.Millisecond, false); e != nil {
		t.Fatal(e)
	}
	if len(p.creates) != 1 || p.creates[0].Success || p.validateCreates("cold") == nil {
		t.Fatal("failed sample discarded")
	}
}
func TestCreationCostElapsedDoesNotChangeAPIResultOrFailure(t *testing.T) {
	for _, ok := range []bool{true, false} {
		p := &creationCostTrace{scope: "cold"}
		sentinel := errors.New("private artificial transport failure")
		c := &switchAPI{costProbe: p, http: &http.Client{Transport: switchTestTransport(func(r *http.Request) (*http.Response, error) {
			if !ok {
				return nil, sentinel
			}
			return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{"state":"READY","backend":"firecracker"}`)), Header: make(http.Header)}, nil
		})}}
		_, e := c.create(context.Background(), "private-unit-only")
		if (ok && e != nil) || (!ok && !errors.Is(e, sentinel)) {
			t.Fatal("API error changed", e)
		}
		if len(p.creates) != 1 || p.creates[0].Success != ok || p.creates[0].ElapsedNS <= 0 {
			t.Fatal("success/failure lost")
		}
	}
}
func TestCreationCostRangeFixedFormatABI(t *testing.T) {
	good := "name: sys_enter_sync_file_range\nfield:int fd; offset:16; size:8; signed:0;\nfield:loff_t offset; offset:24; size:8; signed:0;\nfield:loff_t nbytes; offset:32; size:8; signed:0;\nfield:unsigned int flags; offset:40; size:8; signed:0;\n"
	if e := costRangeFormat([]byte(good)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(good, "name: sys_enter_sync_file_range", "name: sys_enter_other", 1), strings.Replace(good, "size:8", "size:4", 1), strings.Replace(good, "offset:32", "offset:24", 1), strings.Replace(good, "loff_t offset", "long offset", 1), good + "field:int fd; offset:16; size:8; signed:0;\n"} {
		if e := costRangeFormat([]byte(bad)); e == nil {
			t.Fatal("wrong kernel ABI accepted")
		}
	}
}
func TestCreationCostElapsedIncompleteInvalidAndExtraScopes(t *testing.T) {
	for _, scope := range []string{"checkpoint", "cold", "other"} {
		p := &creationCostTrace{scope: scope}
		if p.validateCreates(scope) == nil {
			t.Fatal("empty accepted")
		}
		if scope == "other" && p.beginCreate() == nil {
			t.Fatal("arbitrary scope")
		}
	}
	p := &creationCostTrace{scope: "cold"}
	if e := p.beginCreate(); e != nil {
		t.Fatal(e)
	}
	for _, d := range []time.Duration{0, -1, 901 * time.Second} {
		if p.finishCreate(d, true) == nil {
			t.Fatal("bad time")
		}
	}
}

func TestCreationCostSyntheticUnsignedStorageNotCTypedefSignedness(t *testing.T) {
	// Generated ABI example, not a captured kernel format or runtime artifact.
	raw := []byte("name: sys_enter_syncfs\nfield:int fd; offset:16; size:8; signed:0;\n")
	var actualFD string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "field:int fd;") {
			actualFD = line
		}
	}
	if !strings.Contains(actualFD, "offset:16;") || !strings.Contains(actualFD, "size:8;") || !strings.Contains(actualFD, "signed:0;") {
		t.Fatal("synthetic storage example changed")
	}
	compatible := "name: sys_enter_sync_file_range\n" + actualFD + "\nfield:loff_t offset; offset:24; size:8; signed:0;\nfield:loff_t nbytes; offset:32; size:8; signed:0;\nfield:unsigned int flags; offset:40; size:8; signed:0;\n"
	if e := costRangeFormat([]byte(compatible)); e != nil {
		t.Fatal("unsigned machine-word storage rejected", e)
	}
	for _, bad := range []string{strings.Replace(compatible, "signed:0;", "signed:1;", 1), strings.Replace(compatible, "loff_t nbytes", "unsigned int nbytes", 1), strings.Replace(compatible, "offset:24;", "offset:25;", 1), strings.Replace(compatible, "size:8;", "size:4;", 1)} {
		if costRangeFormat([]byte(bad)) == nil {
			t.Fatal("incorrect storage metadata accepted")
		}
	}
}
func TestCreationCostABIRowsPreserveRejectedFormatsAndRequireFullQualifiedSet(t *testing.T) {
	p := &creationCostTrace{scope: "checkpoint", ordinaryELF: prepareTraceELFSHA, window: 8 << 20, formats: map[string]string{costTraceEvents[0]: "unvalidated actual format"}}
	if _, e := p.abiRows(false); e == nil {
		t.Fatal("partial ABI qualified")
	}
	rows, e := p.abiRows(true)
	if e != nil {
		t.Fatal(e)
	}
	var payload []byte
	for _, row := range rows {
		var frame struct{ Data string }
		if e = json.Unmarshal(row, &frame); e != nil {
			t.Fatal(e)
		}
		chunk, e := base64.StdEncoding.Strict().DecodeString(frame.Data)
		if e != nil {
			t.Fatal(e)
		}
		payload = append(payload, chunk...)
	}
	if !bytes.Contains(payload, []byte("unvalidated actual format")) || !bytes.Contains(payload, []byte("setup_rejected_no_valid_measurement")) {
		t.Fatal("rejected metadata lost")
	}
	for _, name := range costTraceEvents {
		p.formats[name] = "name: " + strings.Split(name, "/")[1] + "\n"
	}
	if _, e = p.abiRows(false); e != nil {
		t.Fatal(e)
	}
}
