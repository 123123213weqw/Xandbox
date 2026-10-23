package sandbox

// AdmissionLimits is trusted service policy/import inventory, never tenant input.
// Zero maximum fields mean that another service layer is being checked. Counts
// are always checked, including imported creating/stopping/reclaiming records.
type AdmissionLimits struct {
	MaxInstances, MaxRecords, MaxSessions                 int
	AllocatedInstances, RetainedRecords, RetainedSessions int
}

// ResourceAdmission lets a real backend bind frontend limits to its immutable
// node envelope. It must be a bounded memory-only check, never filesystem I/O.
type ResourceAdmission interface{ CheckAdmission(AdmissionLimits) error }

func (m *Manager) CheckResourceAdmission(limits AdmissionLimits) error {
	if policy, ok := m.driver.(ResourceAdmission); ok {
		return policy.CheckAdmission(limits)
	}
	return nil
}
