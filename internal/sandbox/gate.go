package sandbox

import "context"

// operationGate serializes one generation's prepare/stop/cleanup. Background
// dispatch never parks a worker on another operation; API waits honor context.
type operationGate chan struct{}

func newOperationGate() operationGate { return make(chan struct{}, 1) }

func (g operationGate) acquire(ctx context.Context, stopped <-chan struct{}) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	select {
	case g <- struct{}{}:
		return true, nil
	case <-stopped:
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (g operationGate) tryAcquire() bool {
	select {
	case g <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g operationGate) release() { <-g }
