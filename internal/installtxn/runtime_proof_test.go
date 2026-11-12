package installtxn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type proofPrivateError struct{ secret string }

func (e *proofPrivateError) Error() string { panic("arbitrary error formatter must not run") }

func TestRuntimeStateProofErrorsPreserveIdentityWithoutFormattingPrivateCause(t *testing.T) {
	private := &proofPrivateError{secret: "private-path-process-record-token"}
	causes := []error{ErrConflict, ErrInventory, context.Canceled, context.DeadlineExceeded, private, errors.Join(private, ErrConflict)}
	for _, cause := range causes {
		e := runtimeProofFailure(proofStopPresignalStateOwner, runtimeProofFailure(proofStateLockOwnerMissing, cause))
		if !errors.Is(e, cause) {
			t.Fatal("cause identity lost")
		}
		var typed *runtimeProofError
		if !errors.As(e, &typed) || typed.stage != proofStopPresignalStateOwner {
			t.Fatal("typed phase lost")
		}
		want := "runtime proof:/stop-presignal-state-owner/state-lock-owner-missing"
		if e.Error() != want || fmt.Sprint(e) != want || fmt.Sprintf("%+v", e) != want {
			t.Fatal("not fixed provenance")
		}
		if cause == private {
			var got *proofPrivateError
			if !errors.As(e, &got) || got != private {
				t.Fatal("typed private cause lost")
			}
		}
		b, err := json.Marshal(e)
		if err != nil || string(b) != "{}" {
			t.Fatal("private fields serialized")
		}
	}
	if runtimeProofFailure(proofStopScope, nil) != nil {
		t.Fatal("success became an error")
	}
}
func TestRuntimeStateProofStageLabelsAreClosedAndBounded(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		e := runtimeProofFailure(runtimeProofStage(i), errors.New("private-payload"))
		got := e.Error()
		if i < len(runtimeProofLabels) {
			label := runtimeProofLabels[i]
			if seen[label] || label == "" || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz-") != "" {
				t.Fatal("non-closed label")
			}
			seen[label] = true
			if got != "runtime proof:/"+label {
				t.Fatal("wrong fixed label")
			}
		} else if got != "runtime proof:/unknown" {
			t.Fatal("out-of-range label exposed")
		}
		if strings.Contains(got, "private") {
			t.Fatal("cause rendered")
		}
	}
	var zero *runtimeProofError
	if zero.Unwrap() != nil || zero.Error() != "runtime proof:" {
		t.Fatal("nil receiver")
	}
	var e error = ErrConflict
	for i := 0; i < 100; i++ {
		e = runtimeProofFailure(proofStopScope, e)
	}
	if strings.Count(e.Error(), "/stop-scope") != 16 || !errors.Is(e, ErrConflict) {
		t.Fatal("trace not bounded or cause lost")
	}
}
