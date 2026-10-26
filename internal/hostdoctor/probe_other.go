//go:build !linux

package hostdoctor

import (
	"context"
	"runtime"
)

func observe(context.Context) observation {
	return observation{os: runtime.GOOS, arch: runtime.GOARCH}
}
