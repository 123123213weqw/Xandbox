//go:build !linux

package installtxn

import "context"

func Apply(context.Context, string, uint64, string) (Result, error) { return Result{}, ErrPlatform }
func Reconcile(context.Context, string) (Result, error)             { return Result{}, ErrPlatform }
func Status(context.Context) (Result, error)                        { return Result{}, ErrPlatform }
func Verify(context.Context) error                                  { return ErrPlatform }
