package telemetry

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFixedBinsAndInvalidObservations(t *testing.T) {
	r := &Registry{}
	r.Observe(CreateCall, time.Millisecond, false)
	r.Observe(CreateCall, 2*time.Millisecond, false)
	r.Observe(CreateCall, 61*time.Second, true)
	r.Observe(operationCount, time.Second, false)
	r.Observe(CreateCall, -1, false)
	var disabled *Registry
	disabled.Observe(CreateCall, time.Second, false)
	s := string(r.Render(Gauges{Records: 3, Allocated: 1}))
	for _, want := range []string{
		`xandbox_operation_seconds_bucket{operation="create_call",outcome="success",le="0.001"} 1`,
		`xandbox_operation_seconds_bucket{operation="create_call",outcome="success",le="0.005"} 2`,
		`xandbox_operation_seconds_count{operation="create_call",outcome="success"} 2`,
		`xandbox_operation_seconds_sum{operation="create_call",outcome="success"} 0.003000`,
		`xandbox_operation_seconds_bucket{operation="create_call",outcome="error",le="+Inf"} 1`,
		"xandbox_records 3\n", "xandbox_allocated 1\n",
	} {
		if !strings.Contains(s, want) {
			t.Fatal("missing observation", want)
		}
	}
	if len(s) > 65536 {
		t.Fatal("exposition exceeds bound", len(s))
	}
}

func TestConcurrentWritesAndScrapesKeepCountInfCoherent(t *testing.T) {
	r := &Registry{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10000 {
				r.Observe(SessionSwitchCall, 3*time.Millisecond, false)
			}
		}()
	}
	for range 100 {
		s := string(r.Render(Gauges{}))
		var inf, count uint64
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, `xandbox_operation_seconds_bucket{operation="session_switch_call",outcome="success",le="+Inf"}`) {
				fmt.Sscanf(line[strings.LastIndex(line, " ")+1:], "%d", &inf)
			}
			if strings.HasPrefix(line, `xandbox_operation_seconds_count{operation="session_switch_call",outcome="success"}`) {
				fmt.Sscanf(line[strings.LastIndex(line, " ")+1:], "%d", &count)
			}
		}
		if inf != count {
			t.Fatal(inf, count)
		}
	}
	wg.Wait()
	s := string(r.Render(Gauges{}))
	if !strings.Contains(s, `xandbox_operation_seconds_count{operation="session_switch_call",outcome="success"} 80000`) {
		t.Fatal("lost observations")
	}
}

func TestObserverHasNoHeapAllocation(t *testing.T) {
	r := &Registry{}
	if n := testing.AllocsPerRun(1000, func() { r.Observe(StopAttempt, time.Millisecond, false) }); n != 0 {
		t.Fatal("observer allocated", n)
	}
}
