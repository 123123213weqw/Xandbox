//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const causeRows = "xandbox_prepare_failed_total{reason=\"io\"} 1\nxandbox_prepare_failed_total{reason=\"quota\"} 2\nxandbox_prepare_failed_total{reason=\"other\"} 3\n"

func TestStartupRefusalRequiresExactClosedOutputAndOrdinaryExitOne(t *testing.T) {
	exit := exec.Command("/bin/false").Run()
	want := "frontend admission differs from immutable node policy"
	line := []byte("sandboxd: " + want + "\n")
	if !exactStartupRefusal(exit, line, want) {
		t.Fatal("ordinary exact refusal not recognized")
	}
	for _, raw := range []string{"", string(line) + "secret\n", "prefix" + string(line), want, "sandboxd: unrelated\n"} {
		if exactStartupRefusal(exit, []byte(raw), want) {
			t.Fatal("arbitrary diagnostic accepted")
		}
	}
	if exactStartupRefusal(nil, line, want) || exactStartupRefusal(context.Canceled, line, want) || exactStartupRefusal(exec.Command("/nonexistent-fixed-test-command").Run(), line, want) {
		t.Fatal("unrelated execution failure accepted")
	}
}

func TestCauseMetricsAreExactClosedAndBounded(t *testing.T) {
	got, e := parsePrepareClasses("# TYPE xandbox_prepare_failed_total counter\nother_metric 71\n" + causeRows)
	if e != nil || got != (prepareClasses{1, 2, 3}) {
		t.Fatal("exact closed rows")
	}
	for _, raw := range []string{
		"", strings.Repeat("x", 65537), causeRows + causeRows,
		strings.Replace(causeRows, `reason="io"`, `reason="path-secret"`, 1),
		strings.Replace(causeRows, " 1\n", " -1\n", 1),
		strings.Replace(causeRows, " 1\n", " NaN\n", 1),
		strings.Replace(causeRows, " 1\n", " 18446744073709551616\n", 1),
		strings.Replace(causeRows, " 1\n", " 1 extra\n", 1),
		strings.Replace(causeRows, " 1\n", "\n", 1),
		causeRows + "xandbox_prepare_failed_total_extra 0\n",
	} {
		if _, e := parsePrepareClasses(raw); e == nil {
			t.Fatal("unknown/ambiguous cause metrics accepted")
		}
	}
}

func TestCauseSocketsHaveNoL0OrArbitraryPathEntry(t *testing.T) {
	for _, socket := range []string{"/srv/state/metrics.sock", "/srv/nq/block/s/metrics.sock", "/srv/nq/inode/s/metrics.sock", "/srv/sq/reserve-barrier-hang/s/metrics.sock"} {
		if !causeSocketAllowed(socket) {
			t.Fatal("fixed case omitted")
		}
		if _, e := fixedPrepareClasses(context.Background(), socket); e == nil {
			t.Fatal("L0 observation")
		}
		if _, e := startPrepareSampler(context.Background(), socket); e == nil {
			t.Fatal("L0 preconnect")
		}
	}
	for _, socket := range []string{"", "/srv/state/api.sock", "/arbitrary/metrics.sock", "/srv/state/../state/metrics.sock"} {
		if causeSocketAllowed(socket) {
			t.Fatal("generic socket accepted")
		}
	}
}

func TestCauseSamplerUsesOnlyTheAlreadyOpenedConnectionAndNeverReconnects(t *testing.T) {
	var requests, connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" || r.Method != "GET" {
			t.Error("unexpected endpoint")
		}
		n := requests.Add(1)
		if n >= 2 {
			w.Header().Set("Connection", "close")
		}
		fmt.Fprintf(w, "xandbox_prepare_failed_total{reason=\"io\"} %d\nxandbox_prepare_failed_total{reason=\"quota\"} 0\nxandbox_prepare_failed_total{reason=\"other\"} 0\n", n)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	conn, e := net.Dial("tcp", server.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, e := samplePreopenedPrepareConnection(ctx, conn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if v, e := s.snapshot(); e != nil || v != (prepareClasses{IO: 1}) {
		t.Fatal("initial observation missing")
	}
	select {
	case <-s.done:
	case <-ctx.Done():
		t.Fatal("reconnect was not rejected")
	}
	if _, e := s.snapshot(); e == nil || connections.Load() != 1 || requests.Load() != 2 {
		t.Fatal("silently reconnected or hid observation failure")
	}
}

func TestCauseSamplerInitialFailureClosesPreopenedConnection(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, e := samplePreopenedPrepareConnection(ctx, client); e == nil || s != nil {
		t.Fatal("cancelled connection accepted")
	}
	if e := peer.SetReadDeadline(time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, e := peer.Read(make([]byte, 1)); e != io.EOF {
		t.Fatal("failed sampler retained connection")
	}
}
