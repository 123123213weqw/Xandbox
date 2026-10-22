package firecracker

import (
	"strings"
	"sync"
	"testing"
)

func TestStartupDiagnosticIsBoundedAndDisabledBeforeTenantWork(t *testing.T) {
	d := &startupDiagnostic{}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			p := []byte(strings.Repeat("x", 5000))
			if n, err := d.Write(p); n != len(p) || err != nil {
				t.Error("diagnostic backpressured stderr")
			}
		}()
	}
	workers.Wait()
	if len(d.text()) != 4096 {
		t.Fatal("unbounded or missing initialization diagnostic")
	}
	d.disable()
	d.Write([]byte("tenant-secret"))
	if d.text() != "" {
		t.Fatal("retained tenant console after readiness")
	}
}
