package hostdoctor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func modelGood() observation {
	return observation{os: "linux", arch: "amd64", pid1: available, manager: available, major: 255,
		cgroup: available, controllers: available, kvm: available, access: available}
}

func TestAllBasicObservationsNeverCertifyDeploymentOrIsolation(t *testing.T) {
	r := summarize(modelGood())
	if !r.BasicPrerequisitesMet || !r.ReadOnly || r.ProductionReady || r.IsolationValidated || r.VMCreated || len(r.Checks) != 8 || len(r.DeferredChecks) != 9 {
		t.Fatal("necessary observations were promoted to readiness", r)
	}
	for _, c := range r.Checks {
		if c.Status != "pass" {
			t.Fatal("complete basic model failed", c)
		}
	}
}

func TestEveryMissingOrUnknownPrerequisiteBlocksBasicSuccess(t *testing.T) {
	for _, kind := range []string{"os", "arch", "pid1", "pid1-unknown", "manager", "old-manager", "zero-manager", "oversize-manager", "cgroup", "cgroup-unknown", "controllers", "controllers-unknown", "device", "device-unknown", "permissions", "permissions-unknown"} {
		t.Run(kind, func(t *testing.T) {
			o := modelGood()
			switch kind {
			case "os":
				o.os = "darwin"
			case "arch":
				o.arch = "arm64"
			case "pid1":
				o.pid1 = unavailable
			case "pid1-unknown":
				o.pid1 = unobserved
			case "manager":
				o.manager = unobserved
			case "old-manager":
				o.major = 249
			case "zero-manager":
				o.major = 0
			case "oversize-manager":
				o.major = 10000
			case "cgroup":
				o.cgroup = unavailable
			case "cgroup-unknown":
				o.cgroup = unobserved
			case "controllers":
				o.controllers, o.missing = unavailable, []string{"io"}
			case "controllers-unknown":
				o.controllers = malformed
			case "device":
				o.kvm = unavailable
			case "device-unknown":
				o.kvm = unobserved
			case "permissions":
				o.access = denied
			case "permissions-unknown":
				o.access = unobserved
			}
			if summarize(o).BasicPrerequisitesMet {
				t.Fatal("missing or unknown prerequisite accepted")
			}
		})
	}
}

func TestVersionFloorAndRunningManagerRequired(t *testing.T) {
	for _, major := range []int{1, 249, 253, 254, 255, 9999} {
		o := modelGood()
		o.major = major
		if summarize(o).BasicPrerequisitesMet != (major >= 254) {
			t.Fatal("version floor changed")
		}
		o.pid1 = unobserved
		if r := summarize(o); r.BasicPrerequisitesMet || r.ObservedSystemdMajor != 0 {
			t.Fatal("unconfirmed manager version projected as observed")
		}
	}
}

func TestProjectionIsClosedAndCollectionsAreNotShared(t *testing.T) {
	o := modelGood()
	o.os, o.arch = "/private/SECRET", "credential=SECRET"
	o.missing = []string{"pids", "io", "io", "SECRET"}
	b, e := json.Marshal(summarize(o))
	if e != nil || strings.Contains(string(b), "SECRET") {
		t.Fatal("unrecognized host input leaked")
	}
	r := summarize(modelGood())
	r.Checks[0].Code = "changed"
	r.DeferredChecks[0] = "changed"
	if next := summarize(modelGood()); next.Checks[0].Code == "changed" || next.DeferredChecks[0] == "changed" {
		t.Fatal("callers share mutable report inventory")
	}
}

func TestCollectCanceledContextDoesNotCertifyPrerequisites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Collect(ctx)
	if r.BasicPrerequisitesMet || r.ProductionReady || r.VMCreated || !r.ReadOnly {
		t.Fatal("canceled observation accepted")
	}
}
