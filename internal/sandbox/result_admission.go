package sandbox

// ResultResourceAdmission binds an actual result store's logical limits to a
// backend's immutable reservation. The check is memory-only, never a constructor
// or filesystem operation. Zero limits mean retention is disabled, not defaults.
type ResultResourceAdmission interface {
	CheckResultAdmission(ResultLimits) error
}

func checkResultResourceAdmission(driver Driver, store ResultStore) error {
	policy, ok := driver.(ResultResourceAdmission)
	if !ok {
		return nil // Other drivers keep their existing contracts; no VM fallback.
	}
	var limits ResultLimits
	if store != nil {
		actual, ok := store.(*FileResultStore)
		if !ok || actual == nil {
			return ErrResultUnavailable
		}
		var e error
		limits, e = actual.resourceResultLimits()
		if e != nil {
			return e
		}
	}
	return policy.CheckResultAdmission(limits)
}
