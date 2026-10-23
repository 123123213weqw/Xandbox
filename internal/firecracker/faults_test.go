package firecracker

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
)

type opaquePolicyError []byte

func (opaquePolicyError) Error() string { panic("must not stringify") }
func (opaquePolicyError) Is(error) bool { panic("must not call Is") }
func (opaquePolicyError) Unwrap() error { panic("must not call Unwrap") }
func TestClosedPolicyAndConcreteSystemClasses(t *testing.T) {
	for _, e := range []*policyFault{ErrAdmissionMismatch, ErrControllerPlacement, ErrIOBackingQueue, ErrIODelegation, ErrBackendBinding, ErrQuotaCapabilities, ErrQuotaFilesystem, ErrQuotaOwnership, ErrQuotaMount} {
		if DiagnosticReason(e) != e.reason || e.Error() == "" || !errors.Is(fmt.Errorf("trusted wrapper: %w", e), e) {
			t.Fatal("typed policy sentinel")
		}
	}
	if DiagnosticReason(&os.PathError{Path: "private", Err: syscall.EIO}) != diagnostics.IOFailure || DiagnosticReason(syscall.EDQUOT) != diagnostics.QuotaExceeded || DiagnosticReason(opaquePolicyError{1}) != diagnostics.Other {
		t.Fatal("concrete class")
	}
}
