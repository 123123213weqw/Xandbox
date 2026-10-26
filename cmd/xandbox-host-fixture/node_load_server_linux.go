//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: decode the fixed ordinary daemon's response observations. Never
// send an extra request, echo/store a raw header or change the original result.
import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var nodeLoadServerNames = [...]string{
	"xa_core_admission", "xa_core_owner_commit", "xa_core_driver", "xa_core_ready_commit",
	"xa_driver_slot", "xa_driver_owner", "xa_driver_quota_reserve", "xa_driver_copy",
	"xa_driver_quota_verify", "xa_driver_activation", "xa_session_intent_commit",
	"xa_session_prepared_commit", "xa_session_active_commit",
}
var nodeLoadServerMetric = regexp.MustCompile(`^([a-z_]+);dur=([0-9]{1,8}\.[0-9]{3});desc="n1"$`)

type nodeLoadServerEntry struct {
	Phase string  `json:"phase"`
	MS    float64 `json:"ms"`
	Calls int     `json:"calls"`
}
type nodeLoadServerCall struct {
	Phase            string                `json:"phase"`
	ResponseObserved bool                  `json:"response_observed"`
	TimingsPresent   bool                  `json:"timings_present"`
	Entries          []nodeLoadServerEntry `json:"entries"`
}

func nodeLoadServerEntries(values []string) ([]nodeLoadServerEntry, bool) {
	entries := []nodeLoadServerEntry{}
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 2048 {
		return entries, false
	}
	parts := strings.Split(values[0], ", ")
	if len(parts) > len(nodeLoadServerNames) {
		return entries, false
	}
	last := -1
	for _, part := range parts {
		match := nodeLoadServerMetric.FindStringSubmatch(part)
		if match == nil {
			return nil, false
		}
		ordinal := -1
		for n, name := range nodeLoadServerNames {
			if name == match[1] {
				ordinal = n
				break
			}
		}
		ms, err := strconv.ParseFloat(match[2], 64)
		if ordinal <= last || ms > 35001 || err != nil {
			return nil, false
		}
		last = ordinal
		entries = append(entries, nodeLoadServerEntry{Phase: match[1], MS: ms, Calls: 1})
	}
	return entries, true
}

func nodeLoadCaptureServer(ctx context.Context, response *http.Response) {
	a, _ := ctx.Value(nodeLoadActorContextKey{}).(*nodeLoadActor)
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.value.Phases) - 1
	if n < 0 || a.value.Phases[n].Ended || a.value.Done || len(a.value.Server) >= 2 {
		a.value.Invalid = true
		return
	}
	phase := a.value.Phases[n].Phase
	if phase != "raw_create" && phase != "canary_open_http" && phase != "canary_switch_http" {
		a.value.Invalid = true
		return
	}
	for _, call := range a.value.Server {
		if call.Phase == phase {
			a.value.Invalid = true
			return
		}
	}
	call := nodeLoadServerCall{Phase: phase, ResponseObserved: response != nil, Entries: []nodeLoadServerEntry{}}
	if response != nil {
		values := response.Header.Values("Server-Timing")
		call.TimingsPresent = len(values) != 0
		if call.TimingsPresent {
			entries, valid := nodeLoadServerEntries(values)
			if !valid {
				a.value.Invalid = true
			} else {
				call.Entries = entries
			}
		}
	}
	a.value.Server = append(a.value.Server, call)
}

func nodeLoadActorClone(v nodeLoadActorSnapshot) nodeLoadActorSnapshot {
	v.Phases = append([]nodeLoadActorPoint{}, v.Phases...)
	v.Server = append([]nodeLoadServerCall{}, v.Server...)
	for n := range v.Server {
		v.Server[n].Entries = append([]nodeLoadServerEntry{}, v.Server[n].Entries...)
	}
	return v
}
