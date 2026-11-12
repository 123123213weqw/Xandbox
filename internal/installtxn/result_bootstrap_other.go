//go:build !linux

package installtxn

import "context"

func ApplyResults(context.Context, string, uint64, string) (Result, error) {
	return Result{}, ErrPlatform
}
func ReconcileResults(context.Context, string) (Result, error) { return Result{}, ErrPlatform }
func StatusResults(context.Context) (Result, error)            { return Result{}, ErrPlatform }
func VerifyResults(context.Context) error                      { return ErrPlatform }
