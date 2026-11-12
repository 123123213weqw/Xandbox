//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resultInspectionRaw(t *testing.T) ([]byte, ResultReservation) {
	t.Helper()
	h := resultHeader()
	j := resultTerminal(h)
	return resultBytes(resultEnvelope{Version: 2, Reservation: h, Result: &retainedOutput{Status: j.Status, FinishedAt: j.FinishedAt, Stdout: []byte(j.Output.Stdout), Stderr: []byte(j.Output.Stderr), ExitCode: j.Output.ExitCode}}), h
}
func TestResultInspectionDecoderExactV2TerminalAndNoPayloadProjection(t *testing.T) {
	raw, header := resultInspectionRaw(t)
	before := append([]byte(nil), raw...)
	r, e := DecodePersistedTerminalResult(raw)
	h := sha256.Sum256(raw)
	if e != nil || r.Reservation != header || r.RawSHA256 != hex.EncodeToString(h[:]) || r.Bytes != int64(len(raw)) || r.ReservedBytes != header.charge() || !bytes.Equal(raw, before) || MaxResultRecordBytes != 2*65_536+16_384 {
		t.Fatal(r, e)
	}
}
func TestResultInspectionInvalidLegacyPendingAndNoncanonicalRefuseZero(t *testing.T) {
	raw, _ := resultInspectionRaw(t)
	for _, kind := range []string{"legacy", "pending", "bad-checksum", "unknown-field", "duplicate", "trailing", "noncanonical", "oversize", "nil", "broken", "version", "output-limit", "invalid-time"} {
		t.Run(kind, func(t *testing.T) {
			r, e := decodeResult(raw)
			if e != nil {
				t.Fatal(e)
			}
			changed := append([]byte(nil), raw...)
			switch kind {
			case "legacy":
				r.Version, r.SHA256 = 1, ""
				changed = resultBytes(r)
			case "pending":
				r.Result = nil
				changed = resultBytes(r)
			case "bad-checksum":
				changed = bytes.Replace(raw, []byte(r.SHA256), []byte(strings.Repeat("0", 64)), 1)
			case "unknown-field":
				changed = append(append([]byte(nil), raw[:len(raw)-2]...), []byte(",\"unknown\":true}\n")...)
			case "duplicate":
				changed = append(append([]byte(nil), raw[:len(raw)-2]...), []byte(",\"version\":2}\n")...)
			case "trailing":
				changed = append(changed, []byte("{}")...)
			case "noncanonical":
				changed = append([]byte(" "), changed...)
			case "oversize":
				changed = bytes.Repeat([]byte{' '}, MaxResultRecordBytes+1)
			case "nil":
				changed = nil
			case "broken":
				changed = []byte("{")
			case "version":
				r.Version = 3
				changed = resultBytes(r)
			case "output-limit":
				r.Reservation.MaxOutputBytes = 65_537
				changed = resultBytes(r)
			case "invalid-time":
				r.Reservation.StartedAt = time.Time{}
				changed = resultBytes(r)
			}
			before := append([]byte(nil), changed...)
			if got, e := DecodePersistedTerminalResult(changed); e == nil || got != (ResultRecordInspection{}) || !bytes.Equal(before, changed) {
				t.Fatal(got, e)
			}
		})
	}
}
func TestResultInspectionProjectionMatchesActualSealedStoreFullRawDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results")
	s := resultOpen(t, path, resultLimits())
	h := resultHeader()
	for _, id := range []string{strings.Repeat("a", 32), strings.Repeat("d", 32)} {
		x := h
		x.JobID = id
		if e := s.Reserve(x); e != nil {
			t.Fatal(e)
		}
		if e := s.Complete(resultTerminal(x)); e != nil {
			t.Fatal(e)
		}
	}
	owner := resultOwner(h)
	owner.State = Destroyed
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	actual, e := s.sealResults(ctx, []Record{owner})
	if e != nil {
		t.Fatal(e)
	}
	p := NewResultInspectionProjection()
	for _, id := range []string{strings.Repeat("a", 32), strings.Repeat("d", 32)} {
		raw, e := os.ReadFile(filepath.Join(path, id+".json"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = p.Add(id, raw); e != nil {
			t.Fatal(e)
		}
	}
	got, e := p.Observation()
	if e != nil || got != actual || got.Records != 2 {
		t.Fatal(got, actual, e)
	}
}
func TestResultInspectionProjectionRejectsAndPoisonsInvalidPrefixes(t *testing.T) {
	raw, h := resultInspectionRaw(t)
	for _, kind := range []string{"nil", "zero", "name", "duplicate", "descending", "filename-binding", "corrupt", "records", "byte-cap", "reservation-cap"} {
		t.Run(kind, func(t *testing.T) {
			p := NewResultInspectionProjection()
			id := h.JobID
			input := raw
			switch kind {
			case "nil":
				p = nil
			case "zero":
				p = &ResultInspectionProjection{}
			case "name":
				id = "../bad"
			case "duplicate":
				if _, e := p.Add(id, raw); e != nil {
					t.Fatal(e)
				}
			case "descending":
				p.last = strings.Repeat("f", 32)
			case "filename-binding":
				id = strings.Repeat("b", 32)
			case "corrupt":
				input = []byte("{")
			case "records":
				p.count = MaxResultRecords
			case "byte-cap":
				p.bytes = MaxResultBytes
			case "reservation-cap":
				p.reserved = MaxResultBytes
			}
			if row, e := p.Add(id, input); e == nil || row != (ResultRecordInspection{}) {
				t.Fatal(row, e)
			}
			if o, e := p.Observation(); e == nil || o != (ResultClosureObservation{}) {
				t.Fatal(o, e)
			}
			if row, e := p.Add(h.JobID, raw); e == nil || row != (ResultRecordInspection{}) {
				t.Fatal("rejected prefix resumed", row, e)
			}
		})
	}
	empty := NewResultInspectionProjection()
	if o, e := empty.Observation(); e != nil || !o.Valid() || o.Records != 0 || o.Bytes != 0 || o.ReservedBytes != 0 {
		t.Fatal(o, e)
	}
}
