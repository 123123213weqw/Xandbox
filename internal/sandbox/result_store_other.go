//go:build !linux && !darwin

package sandbox

// Private result storage requires supported Unix ownership/descriptor semantics.
type FileResultStore struct{}

func OpenResultStore(string, ResultLimits) (*FileResultStore, error) {
	return nil, ErrResultUnavailable
}
func (*FileResultStore) Close() error                         { return nil }
func (*FileResultStore) Bind([]Record) (bool, error)          { return false, ErrResultUnavailable }
func (*FileResultStore) Reserve(ResultReservation) error      { return ErrResultUnavailable }
func (*FileResultStore) Complete(Job) error                   { return ErrResultUnavailable }
func (*FileResultStore) Get(Ref, string, string) (Job, error) { return Job{}, ErrResultUnavailable }
