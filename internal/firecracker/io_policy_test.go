package firecracker

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func ioPolicy() IOPolicy {
	return IOPolicy{Version: 1, FilesystemDevice: "8:3", Device: "8:0", BytesPerSecond: 8 << 20, OperationsPerSecond: 4096}
}

func TestIOPolicyStrictBoundsAndDeviceSyntax(t *testing.T) {
	p := ioPolicy()
	if e := p.validate(); e != nil {
		t.Fatal(e)
	}
	for _, dev := range []string{"", "0:3", "08:3", "8:03", "8:0\n", "-1:0", "8:0 rbps=max", "4096:0", "8:1048576", "8:0:1"} {
		q := p
		q.Device = dev
		if q.validate() == nil {
			t.Fatalf("invalid device accepted: %q", dev)
		}
		q.Device, q.FilesystemDevice = p.Device, dev
		if q.validate() == nil {
			t.Fatalf("invalid filesystem device accepted: %q", dev)
		}
	}
	for _, change := range []func(*IOPolicy){
		func(p *IOPolicy) { p.Version = 0 }, func(p *IOPolicy) { p.Version = 2 },
		func(p *IOPolicy) { p.BytesPerSecond = 0 }, func(p *IOPolicy) { p.BytesPerSecond = (1 << 20) - 1 },
		func(p *IOPolicy) { p.BytesPerSecond = (1 << 30) + 1 }, func(p *IOPolicy) { p.BytesPerSecond = math.MaxUint64 },
		func(p *IOPolicy) { p.OperationsPerSecond = 127 }, func(p *IOPolicy) { p.OperationsPerSecond = 65537 },
	} {
		q := p
		change(&q)
		cfg := policy()
		cfg.IO = &q
		if cfg.validate() == nil {
			t.Fatal("invalid operator IO policy accepted")
		}
	}
}

func TestIOReadbackCannotDropDirectionsOrAcceptUnlimitedOrDuplicateKeys(t *testing.T) {
	p := ioPolicy()
	if e := p.verifyKernelLimit("8:0 wiops=4096 riops=4096 wbps=8388608 rbps=8388608\n"); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"", "8:0 rbps=8388608", strings.Replace(p.kernelLine(), "8:0", "8:1", 1),
		strings.Replace(p.kernelLine(), "rbps=8388608", "rbps=max", 1), strings.Replace(p.kernelLine(), "riops=4096", "wiops=4096", 1),
		p.kernelLine() + " extra=1", p.kernelLine() + "\n" + p.kernelLine(), strings.Replace(p.kernelLine(), " rbps", "\nrbps", 1)} {
		if p.verifyKernelLimit(raw) == nil {
			t.Fatalf("bad IO readback accepted: %q", raw)
		}
	}
}

func TestIOPolicyIsImmutableBackendBindingAndNilPreservesLegacyJSON(t *testing.T) {
	cfg := policy()
	raw, _ := json.Marshal(cfg)
	if strings.Contains(string(raw), `"io"`) {
		t.Fatal("nil IO policy changed legacy binding")
	}
	p := ioPolicy()
	cfg.IO = &p
	dir := t.TempDir()
	if _, e := newRegistry(dir, cfg, nil); e != nil {
		t.Fatal(e)
	}
	changed := cfg
	changed.IO = nil
	if _, e := newRegistry(dir, changed, nil); e == nil {
		t.Fatal("removed bound IO policy without migration")
	}
	q := p
	q.BytesPerSecond *= 2
	changed.IO = &q
	if _, e := newRegistry(dir, changed, nil); e == nil {
		t.Fatal("changed bound IO policy without migration")
	}
	if _, e := newRegistry(dir, cfg, nil); e != nil {
		t.Fatal(e)
	}
}

func TestFrontendBudgetIsExplicitAndLegacyDriveUnchanged(t *testing.T) {
	drive := workspaceDrive(nil)
	if len(drive) != 4 || drive["rate_limiter"] != nil {
		t.Fatal("legacy drive policy changed")
	}
	p := ioPolicy()
	limit := workspaceDrive(&p)["rate_limiter"].(ioRateLimit)
	if limit.Bandwidth.Size != p.BytesPerSecond || limit.Ops.Size != p.OperationsPerSecond ||
		limit.Bandwidth.RefillTime != 1000 || limit.Ops.RefillTime != 1000 || limit.Bandwidth.OneTimeBurst != 0 || limit.Ops.OneTimeBurst != 0 {
		t.Fatal("unbounded or mismatched frontend buckets")
	}
}
