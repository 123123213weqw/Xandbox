//go:build !linux

package releasestore

import "context"

func Publish(context.Context, string, uint64, string) (Result, error) { return Result{}, ErrPlatform }
func Status(context.Context) (Result, error)                          { return Result{}, ErrPlatform }
