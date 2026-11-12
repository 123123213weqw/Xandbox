//go:build linux

package firecracker

import (
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestInspectionResultsConcreteDriverMemoryAdmission(t *testing.T) {
	for _, kind := range []string{"matched", "disabled", "different"} {
		t.Run(kind, func(t *testing.T) {
			// The real method on an inert private driver value. NEVER New, KVM,
			// quota/cgroup construction or a positive native acceptance claim.
			c := resultsPolicyConfig()
			d := &driver{cfg: c}
			l := c.Results.Limits()
			if kind == "disabled" {
				l = sandbox.ResultLimits{}
			}
			if kind == "different" {
				l.Records--
			}
			if e := d.CheckResultAdmission(l); (e == nil) != (kind == "matched") {
				t.Fatal("actual driver method bypassed immutable match", e)
			}
		})
	}
}
