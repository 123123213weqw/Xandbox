package firecracker

import "github.com/123123213weqw/Xandbox/internal/diagnostics"

// policyFault is sealed to this package. Its message is a constant diagnostic
// class, never operator/tenant input. Errors remain usable as sentinels by
// errors.Is without requiring the logger to traverse arbitrary error objects.
type policyFault struct {
	reason  diagnostics.Reason
	message string
}

func (e *policyFault) Error() string { return e.message }

var (
	ErrAdmissionMismatch   = &policyFault{diagnostics.NodeAdmission, "frontend admission differs from immutable node policy"}
	ErrControllerPlacement = &policyFault{diagnostics.NodePlacement, "controller/publisher must be inside node control subtree"}
	ErrIOBackingQueue      = &policyFault{diagnostics.IOBackingQueue, "IO policy must name the exact runtime backing queue"}
	ErrIODelegation        = &policyFault{diagnostics.IODelegation, "configured IO policy requires delegated io controller"}
	ErrBackendBinding      = &policyFault{diagnostics.BackendBinding, "backend binding changed; explicit offline migration is required"}
	ErrQuotaCapabilities   = &policyFault{diagnostics.QuotaCapabilities, "quota requires CAP_SYS_RESOURCE absent from all capability sets"}
	ErrQuotaFilesystem     = &policyFault{diagnostics.QuotaFilesystem, "quota runtime filesystem UUID changed"}
	ErrQuotaOwnership      = &policyFault{diagnostics.QuotaOwnership, "unowned nonempty quota record requires operator reconciliation"}
	ErrQuotaMount          = &policyFault{diagnostics.QuotaMount, "quota requires the exact writable ext4 mount with enforced prjquota"}
)

// DiagnosticReason is for errors returned by this sealed backend. No caller
// method is invoked: only a sealed policy class or concrete OS wrapper fields.
// Unknown wrappers retain the closed Other class rather than guessing via text.
func DiagnosticReason(err error) diagnostics.Reason {
	if e, ok := err.(*policyFault); ok && e != nil {
		return e.reason
	}
	return diagnostics.SystemReason(err)
}
