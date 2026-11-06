//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: read the fixed daemon's existing response; never issue another
// request, retain raw headers, select a tenant, or change the API result.
import (
	"errors"
	"math"
	"net/http"
)

type costCreateServer struct {
	Status  string                `json:"status"`
	Entries []nodeLoadServerEntry `json:"entries"`
}

func costCreateServerEntriesValid(entries []nodeLoadServerEntry) bool {
	// Raw POST /v1/sandboxes has the ten core/driver spans, not session spans.
	if len(entries) != 10 {
		return false
	}
	for i, entry := range entries {
		if entry.Phase != nodeLoadServerNames[i] || entry.Calls != 1 || math.IsNaN(entry.MS) || math.IsInf(entry.MS, 0) || entry.MS < 0 || entry.MS > 35001 {
			return false
		}
	}
	return true
}

func costCreateServerFits(entries []nodeLoadServerEntry, elapsedNS int64) bool {
	if !costCreateServerEntriesValid(entries) || elapsedNS <= 0 {
		return false
	}
	// Only arithmetic consistency of known source nesting. Millisecond headers
	// round each duration to 0.001; this is NOT syscall/critical-path alignment.
	const roundingSlackMS = 0.01
	var driverMS float64
	for _, entry := range entries[4:] {
		driverMS += entry.MS
	}
	topMS := entries[0].MS + entries[1].MS + entries[2].MS + entries[3].MS
	return driverMS <= entries[2].MS+roundingSlackMS && topMS <= float64(elapsedNS)/1e6+roundingSlackMS
}

func (t *creationCostTrace) captureCreateServer(response *http.Response) {
	if t == nil {
		return
	}
	if !t.createInFlight || t.createServer.Status != "not_observed" {
		t.serverObservationInvalid = true
		return
	}
	t.createServer.Status = "no_response"
	if response == nil {
		return
	}
	t.createServer.Status = "missing"
	values := response.Header.Values("Server-Timing")
	if len(values) == 0 {
		return
	}
	t.createServer.Status = "invalid"
	entries, ok := nodeLoadServerEntries(values)
	if !ok || !costCreateServerEntriesValid(entries) {
		return
	}
	t.createServer = costCreateServer{Status: "observed", Entries: entries}
}

func (t *creationCostTrace) validateCreateServers() error {
	if t == nil || t.serverObservationInvalid || t.validateCreates(t.scope) != nil {
		return errors.New("invalid fixed create server observation")
	}
	for _, create := range t.creates {
		if create.ServerTiming.Status != "observed" || !costCreateServerFits(create.ServerTiming.Entries, create.ElapsedNS) {
			return errors.New("complete fixed create server timings required")
		}
	}
	return nil
}
