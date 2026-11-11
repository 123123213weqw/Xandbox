//go:build !linux && !darwin

package sandbox

import "context"

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

func (*FileResultStore) resultsAlive() bool { return false }
func (*FileResultStore) sealResults(context.Context, []Record) (ResultClosureObservation, error) {
	return ResultClosureObservation{}, ErrResultUnavailable
}
