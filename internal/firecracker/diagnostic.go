package firecracker

import "sync"

// startupDiagnostic retains at most 4 KiB of initialization stderr in private
// controller memory. It is cleared/disabled before READY; task console is never
// retained. On startup failure only, the private ledger can retain this text.
type startupDiagnostic struct {
	mu       sync.Mutex
	data     []byte
	disabled bool
}

func (d *startupDiagnostic) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := len(p)
	if !d.disabled {
		if len(p) > 4096-len(d.data) {
			p = p[:4096-len(d.data)]
		}
		d.data = append(d.data, p...)
	}
	return n, nil
}

func (d *startupDiagnostic) text() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return string(d.data)
}

func (d *startupDiagnostic) disable() {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.data)
	d.data, d.disabled = nil, true
}
