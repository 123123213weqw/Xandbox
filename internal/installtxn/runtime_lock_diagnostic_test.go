package installtxn

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeStateLockDiagnosticClosedShapeAndFormatting(t *testing.T) {
	typ := reflect.TypeOf(runtimeLockAmbiguity{})
	if typ.NumField() != 2 {
		t.Fatal("review new diagnostic fields")
	}
	for i, name := range []string{"count", "shape"} {
		f := typ.Field(i)
		if f.Name != name || f.PkgPath == "" || f.Type.Kind() != reflect.Uint8 {
			t.Fatal("diagnostics may retain only two private bounded enum bytes")
		}
	}
	counts := map[int]string{1: "two", 2: "three", 3: "many"}
	shapes := map[int]string{1: "exact-text", 2: "same-ordinal", 3: "different-ordinal"}
	private := &proofPrivateError{secret: "private-ordinal-path-pid-device-inode-token"}
	for count := 0; count < 256; count++ {
		for shape := 0; shape < 256; shape++ {
			e := &runtimeProofError{stage: proofStateLockOwnerAmbiguous, cause: private, lock: runtimeLockAmbiguity{uint8(count), uint8(shape)}}
			want := "runtime proof:/state-lock-owner-ambiguous"
			if count != 0 || shape != 0 {
				if counts[count] != "" && shapes[shape] != "" {
					want += "/lock-rows-" + counts[count] + "/" + shapes[shape]
				} else {
					want += "/lock-rows-unavailable"
				}
			}
			if e.Error() != want || !errors.Is(e, private) {
				t.Fatal("non-closed diagnostic or cause lost")
			}
		}
	}
	e := &runtimeProofError{stage: proofStateLockOwnerAmbiguous, cause: private, lock: runtimeLockAmbiguity{3, 3}}
	want := "runtime proof:/state-lock-owner-ambiguous/lock-rows-many/different-ordinal"
	if fmt.Sprint(e) != want || fmt.Sprintf("%+v", e) != want {
		t.Fatal("private cause formatter ran or fixed summary changed")
	}
	data, err := json.Marshal(e)
	if err != nil || string(data) != "{}" {
		t.Fatal("diagnostics serialized private fields")
	}
	e.stage = proofStopScope
	if e.Error() != "runtime proof:/stop-scope" {
		t.Fatal("unrelated proof stage acquired lock diagnostics")
	}
}

func TestRuntimeStateLockDiagnosticBucketsAndWrappedCause(t *testing.T) {
	for _, n := range []int{-1, 0, 1, 2, 3, 4, 5, 65536, math.MaxInt} {
		for _, sameText := range []bool{false, true} {
			for _, sameOrdinal := range []bool{false, true} {
				e := runtimeLockAmbiguityFailure(n, sameText, sameOrdinal)
				want := "runtime proof:/state-lock-owner-ambiguous"
				if n >= 2 {
					count, shape := "many", "different-ordinal"
					if n == 2 {
						count = "two"
					} else if n == 3 {
						count = "three"
					}
					if sameText && sameOrdinal {
						shape = "exact-text"
					} else if sameOrdinal {
						shape = "same-ordinal"
					}
					want += "/lock-rows-" + count + "/" + shape
				}
				if e.Error() != want || !errors.Is(e, ErrConflict) || errors.Is(e, ErrInventory) {
					t.Fatal("bucket changed or cause/ambiguity waived")
				}
				wrapped := runtimeProofFailure(proofStopOriginalPeers, e)
				if wrapped.Error() != strings.Replace(want, "runtime proof:", "runtime proof:/stop-original-peers", 1) || !errors.Is(wrapped, ErrConflict) {
					t.Fatal("actual outer provenance lost inner topology or conflict")
				}
			}
		}
	}
	var e error = ErrConflict
	for i := 0; i < 100; i++ {
		e = &runtimeProofError{stage: proofStateLockOwnerAmbiguous, cause: e, lock: runtimeLockAmbiguity{3, 3}}
	}
	if strings.Count(e.Error(), "/lock-rows-many/different-ordinal") != 16 || len(e.Error()) > 2048 || !errors.Is(e, ErrConflict) {
		t.Fatal("diagnostic chain unbounded or cause lost")
	}
}
