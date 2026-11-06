//go:build linux && xandbox_host_fixture

package main

// Test-only startup selection, never a tenant RPC or production daemon option.
import "errors"

type creationCostMode string

const (
	creationCostOff     creationCostMode = "off"
	creationCostObserve creationCostMode = "observe"
	creationCostMaximum creationCostMode = "maximum"
)

// Assigned once by main, before any service goroutine starts. Default is OFF.
var configuredCreationCostMode = creationCostOff

func parseCreationCostMode(value, mode, config string, nargs int) (creationCostMode, error) {
	selected := creationCostMode(value)
	if selected == creationCostOff {
		return selected, nil
	}
	if (selected != creationCostObserve && selected != creationCostMaximum) || mode != "node-budget" || config != "" || nargs != 0 {
		return creationCostOff, errors.New("creation-cost diagnostics require explicit healthy node-budget startup without extra arguments")
	}
	return selected, nil
}
func withCreationCostMode(mode creationCostMode, begin func() (*creationCostTrace, error)) (*creationCostTrace, error) {
	switch mode {
	case creationCostOff:
		return nil, nil
	case creationCostObserve, creationCostMaximum:
		return begin()
	default:
		return nil, errors.New("unknown test-only creation-cost mode")
	}
}
func costNormalPayload(mode creationCostMode, original []byte) ([]byte, error) {
	switch mode {
	case creationCostObserve:
		return original, nil
	case creationCostMaximum:
		return costDeliveryMaximumPayload(original)
	default:
		return nil, errors.New("inactive creation-cost collection")
	}
}
func collectCreationCostIfEnabled(probe *creationCostTrace, scope string) error {
	if probe == nil {
		return nil
	}
	return probe.collect(scope)
}
func mergeCreationCostFinish(probe *creationCostTrace, current *error) {
	if probe == nil {
		return
	}
	if err := probe.finish(); err != nil {
		*current = errors.Join(*current, err)
	}
}
