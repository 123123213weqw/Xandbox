//go:build !linux

package installtxn

import "context"

func ReconfigureResults(context.Context, string, uint64, string) (Result, error) {
	return Result{}, ErrPlatform
}
func ReconcileResultsPolicy(context.Context, string) (Result, error) { return Result{}, ErrPlatform }
