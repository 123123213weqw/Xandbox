//go:build !linux

package policycontrol

import (
	"context"
	"errors"
)

func RequestPolicy(context.Context, int, PolicyCommand) (PolicyStatus, error) {
	return PolicyStatus{}, errors.New("Linux root operator required")
}
