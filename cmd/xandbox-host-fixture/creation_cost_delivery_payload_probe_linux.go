//go:build linux && xandbox_host_fixture

package main

// PRIVATE TRANSPORT PROBE ONLY. The actual canonical-A workload/JSON is retained
// byte-for-byte; fixed trailing JSON whitespace fills the existing wire bound.
// This is deliberately synthetic telemetry, not a performance comparison.
import (
	"encoding/json"
	"errors"
)

func costDeliveryMaximumPayload(original []byte) ([]byte, error) {
	if len(original) == 0 || len(original) > 1<<20 || !json.Valid(original) {
		return nil, errors.New("private maximum delivery requires bounded original JSON")
	}
	padded := make([]byte, 1<<20)
	copy(padded, original)
	for i := len(original); i < len(padded); i++ {
		padded[i] = ' '
	}
	return padded, nil
}
