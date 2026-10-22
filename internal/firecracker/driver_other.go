//go:build !linux

package firecracker

import (
	"errors"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func New(stateDir, configPath string, records []sandbox.Record) (sandbox.Driver, error) {
	return nil, errors.New("Firecracker requires Linux/KVM; no host-execution fallback")
}
