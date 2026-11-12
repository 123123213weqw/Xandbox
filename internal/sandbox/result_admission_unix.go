//go:build linux || darwin

package sandbox

// The ordinary store may load records above newly lowered admission limits to
// preserve recovery. An immutable real-node reservation must NOT reinterpret
// that as fitting a smaller envelope. Refuse without eviction, rewrite, sync or
// lower-policy restoration. This inspects the actual loaded index, not arbitrary
// caller counts, and is not a complete live disk/Stop/activation certificate.
func (s *FileResultStore) resourceResultLimits() (ResultLimits, error) {
	if s == nil {
		return ResultLimits{}, ErrResultUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.limits // Immutable after OpenResultStore, not caller-owned metadata.
	if s.closed.Load() || !l.valid() || len(s.entries) > l.Records || s.bytes < 0 || s.bytes > l.Bytes {
		return ResultLimits{}, ErrResultCapacity
	}
	var total int64
	for _, charge := range s.tenantBytes {
		if charge < 0 || charge > l.TenantBytes || charge > l.Bytes-total {
			return ResultLimits{}, ErrResultCapacity
		}
		total += charge
	}
	if total != s.bytes {
		return ResultLimits{}, ErrResultUnavailable
	}
	return l, nil
}

// CheckResourceCapacity checks CURRENT loaded reservations, including uncertain
// records. No resource is freed and no backend or worker is started.
func (s *FileResultStore) CheckResourceCapacity() error {
	_, e := s.resourceResultLimits()
	return e
}
