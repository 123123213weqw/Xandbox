//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: use the existing metrics read. No new management request, timing
// selector, console write, file, worker or protocol acceptance exception.
import (
	"regexp"
	"strconv"
	"strings"
)

var nodeLoadActivityKinds = [...]string{"raw_create", "session_open", "session_switch"}
var nodeLoadActivityPhases = [...]string{
	"xa_core_admission", "xa_core_owner_commit", "xa_core_driver", "xa_core_ready_commit",
	"xa_driver_slot", "xa_driver_owner", "xa_driver_quota_reserve", "xa_driver_copy",
	"xa_driver_quota_verify", "xa_driver_activation", "xa_session_intent_commit",
	"xa_session_prepared_commit", "xa_session_active_commit",
	"xa_driver_permit_wait", "xa_driver_node_check",
}

type nodeLoadCreationActivity struct {
	Version  int           `json:"version"`
	Requests [3]uint64     `json:"requests"`
	Phases   [3][15]uint64 `json:"phases"`
}

var nodeLoadActivityRequest = regexp.MustCompile(`^xandbox_creation_requests_active\{operation="([a-z_]+)"\} ([0-9]+)$`)
var nodeLoadActivityPhase = regexp.MustCompile(`^xandbox_creation_phases_active\{operation="([a-z_]+)",phase="([a-z_]+)"\} ([0-9]+)$`)

func nodeLoadActivityOrdinal(names []string, name string) int {
	for i, known := range names {
		if name == known {
			return i
		}
	}
	return -1
}

// Status is closed; missing/disabled/invalid/malformed NEVER means zero work.
// Counters are independent observations: do not compare phase <= requests or
// infer one actor's identity, ordering, latency, completion or resource safety.
func nodeLoadReadCreationActivity(b []byte) (status string, result *nodeLoadCreationActivity) {
	if len(b) > 256<<10 {
		return "malformed", nil
	}
	v := &nodeLoadCreationActivity{Version: 1}
	seen := map[string]bool{}
	enabled, invalid, count := -1, -1, 0
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "xandbox_creation_") {
			continue
		}
		count++
		if count > 50 {
			return "malformed", nil
		}
		name, number, ok := strings.Cut(line, " ")
		if !ok || seen[name] {
			return "malformed", nil
		}
		seen[name] = true
		n, e := strconv.ParseUint(number, 10, 64)
		if e != nil || strconv.FormatUint(n, 10) != number || n > 1<<20 {
			return "malformed", nil
		}
		switch name {
		case "xandbox_creation_activity_enabled":
			if n > 1 {
				return "malformed", nil
			}
			enabled = int(n)
		case "xandbox_creation_activity_invalid":
			if n > 1 {
				return "malformed", nil
			}
			invalid = int(n)
		default:
			if m := nodeLoadActivityRequest.FindStringSubmatch(line); m != nil {
				kind := nodeLoadActivityOrdinal(nodeLoadActivityKinds[:], m[1])
				if kind < 0 {
					return "malformed", nil
				}
				v.Requests[kind] = n
			} else if m := nodeLoadActivityPhase.FindStringSubmatch(line); m != nil {
				kind := nodeLoadActivityOrdinal(nodeLoadActivityKinds[:], m[1])
				phase := nodeLoadActivityOrdinal(nodeLoadActivityPhases[:], m[2])
				if kind < 0 || phase < 0 {
					return "malformed", nil
				}
				v.Phases[kind][phase] = n
			} else {
				return "malformed", nil
			}
		}
	}
	if count == 0 {
		return "missing", nil
	}
	if count != 50 || enabled < 0 || invalid < 0 {
		return "malformed", nil
	}
	if invalid != 0 {
		return "invalid", nil
	}
	if enabled == 0 {
		return "disabled", nil
	}
	return "observed", v
}

func nodeLoadCloneCreationActivity(v *nodeLoadCreationActivity) *nodeLoadCreationActivity {
	if v == nil {
		return nil
	}
	copy := *v // Arrays are copied, no shared mutable slices/maps or identities.
	return &copy
}
