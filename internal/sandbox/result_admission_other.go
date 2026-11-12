//go:build !linux && !darwin

package sandbox

func (*FileResultStore) resourceResultLimits() (ResultLimits, error) {
	return ResultLimits{}, ErrResultUnavailable
}
func (*FileResultStore) CheckResourceCapacity() error { return ErrResultUnavailable }
