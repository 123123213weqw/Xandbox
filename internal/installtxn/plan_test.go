package installtxn

import (
	"bytes"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
)

func samplePlan() Plan {
	hash := strings.Repeat("a", 64)
	a := func(name string) firecracker.Asset {
		return firecracker.Asset{Path: "/bootstrap/" + name, SHA256: hash}
	}
	return Plan{Version: 1, ReleaseRevision: 1, Release: hash, Self: a("xandbox-install"), Backend: a("backend.json"), Auth: a("auth.json"), Gateway: a("gateway.json"), Certificate: a("leaf.pem"), PrivateKey: a("leaf.key"), DevicePath: "/dev/vda", Frontend: launch.Frontend{MaxInstances: 4, MaxRecords: 1024, MaxTenantRecords: 512, MaxSessions: 32, MaxTenantSessions: 16, SessionHistory: 64, StopWorkers: 4, CleanupWorkers: 2, WorkQueueSize: 32, Metrics: true}, Parent: launch.ParentEnvelope{MemoryMax: 15 << 29, PidsMax: 512, CPUQuota: 800000, IOBytesPerSecond: 512 << 20, IOOperationsPerSecond: 16384}, Ingress: launch.ParentEnvelope{MemoryMax: 512 << 20, PidsMax: 64, CPUQuota: 200000, IOBytesPerSecond: 64 << 20, IOOperationsPerSecond: 2048}, Reserve: launch.ParentEnvelope{MemoryMax: 2 << 30, PidsMax: 64, CPUQuota: 200000, IOBytesPerSecond: 128 << 20, IOOperationsPerSecond: 4096}, Capacity: launch.ParentEnvelope{MemoryMax: 12 << 30, PidsMax: 1024, CPUQuota: 1200000, IOBytesPerSecond: 1 << 30, IOOperationsPerSecond: 32768}}
}
func TestPlanClosedAndBounded(t *testing.T) {
	p := samplePlan()
	if _, e := Decode(encode(p)); e != nil {
		t.Fatal(e)
	}
	changes := map[string]func(*Plan){"version": func(p *Plan) { p.Version = 2 }, "zero-publication": func(p *Plan) { p.ReleaseRevision = 0 }, "unbound": func(p *Plan) { p.Release = "latest" }, "shell-device": func(p *Plan) { p.DevicePath = "/dev/vda;sh" }, "target-source": func(p *Plan) { p.Auth.Path = Root + "/auth.json" }, "state-source": func(p *Plan) { p.Backend.Path = stateDir + "/anything" }, "duplicate-source": func(p *Plan) { p.Auth.Path = p.Backend.Path }, "relative": func(p *Plan) { p.Self.Path = "relative" }, "alias": func(p *Plan) { p.Auth.Path = "/bootstrap/../else" }, "unit-source": func(p *Plan) { p.Auth.Path = UnitDir + "/xandbox.service" }, "bad-front": func(p *Plan) { p.Frontend.MaxInstances = 0 }, "under-capacity": func(p *Plan) { p.Capacity.MemoryMax = p.Parent.MemoryMax }, "rounding": func(p *Plan) { p.Parent.CPUQuota = 800001 }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p := samplePlan()
			change(&p)
			_, e := Decode(encode(p))
			if name == "rounding" {
				art := map[string]Artifact{}
				for _, r := range roles {
					art[r] = Artifact{r, strings.Repeat("a", 64), 10}
				}
				_, e = render(p, "1:1", art)
			}
			if e == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	for _, raw := range [][]byte{append(bytes.TrimSuffix(encode(p), []byte("}\n")), []byte(`,"unknown":true}`)...), []byte(`{"version":1,"version":1}`), bytes.Repeat([]byte(" "), MaxPlan+1), append(encode(p), []byte("{}")...)} {
		if _, e := Decode(raw); e == nil {
			t.Fatal("nonclosed plan accepted")
		}
	}
}
func TestRenderedCompositionHasOneGateBeforeOriginalLauncher(t *testing.T) {
	p := samplePlan()
	art := map[string]Artifact{}
	for _, r := range roles {
		art[r] = Artifact{r, strings.Repeat("a", 64), 10}
	}
	files, e := render(p, "1:1", art)
	if e != nil {
		t.Fatal(e)
	}
	main := string(files[UnitDir+"/"+MainUnit])
	ingress := string(files[UnitDir+"/"+IngressUnit])
	gate := "ExecStartPre=" + SelfPath + " verify\n"
	if strings.Count(main, gate) != 1 || strings.Index(main, gate) > strings.Index(main, "ExecStart=/usr/libexec/xandbox-launch") || !strings.Contains(main, "ExecStartPost=/usr/libexec/xandbox-ready") || !strings.Contains(main, "DelegateSubgroup=bootstrap") {
		t.Fatal("composition changed", main)
	}
	for _, bad := range []string{"ExecStop=", "/bin/sh", "resume", "Restart=always", "reset-failed"} {
		if strings.Contains(main, bad) || strings.Contains(ingress, bad) {
			t.Fatal("hidden operation", bad)
		}
	}
	if !strings.Contains(ingress, "BindsTo="+MainUnit) || !strings.Contains(ingress, "After="+MainUnit) || !strings.Contains(ingress, "WantedBy="+MainUnit) {
		t.Fatal("dependency changed")
	}
}
