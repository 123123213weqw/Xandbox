package gateway

// FailureCode is a closed vocabulary. Never return an arbitrary error string:
// filesystem/network errors may include operator paths or sensitive values.
func FailureCode(err error) string {
	if err == nil {
		return "NONE"
	}
	switch err.Error() {
	case "root gateway supervisor required", "invalid gateway configuration", "cannot read private gateway configuration":
		return "CONFIGURATION"
	case "invalid gateway executable root", "cannot start unprivileged gateway child":
		return "EXECUTABLE_ROOT"
	case "invalid tenant socket binding", "cannot read backend authority", "invalid backend authority":
		return "BACKEND_BINDING"
	case "gateway durable policy state rejected", "gateway durable policy commit rejected":
		return "POLICY_STATE"
	case "invalid gateway policy", "cannot read gateway certificate", "cannot read gateway private key", "cannot seal gateway policy":
		return "POLICY_VALIDATION"
	case "gateway reload rejected; closing ingress", "gateway reload revision rejected; closing ingress", "gateway reload persistence rejected; closing ingress", "gateway reload already pending":
		return "POLICY_RELOAD"
	case "gateway child readiness deadline exceeded":
		return "CHILD_READINESS"
	case "gateway child failed", "gateway child ended unexpectedly":
		return "CHILD_FAILED"
	case "gateway child capability closed", "gateway root capability lost", "gateway heartbeat failed":
		return "CAPABILITY_LOST"
	case "unprivileged gateway identity required", "gateway supplemental groups forbidden", "gateway capabilities must be empty", "cannot verify gateway capabilities", "cannot set gateway no-new-privileges", "cannot bound gateway resource limits":
		return "CHILD_PRIVILEGES"
	case "gateway executable-only root required":
		return "CHILD_ROOT"
	case "gateway TLS listen failed", "gateway TLS server ended":
		return "TLS_LISTENER"
	case "sealed root policy descriptor required", "read-only policy descriptor required", "invalid sealed gateway policy":
		return "SEALED_POLICY"
	}
	return "UNAVAILABLE"
}
