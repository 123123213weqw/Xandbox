package launch

import (
	"reflect"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
)

// These are the original in-memory group MODELs, never kernel cgroup writes.
func TestRetainedLaunchGroupPreparationKeepsOriginalEnvelopeAndSelfLast(t *testing.T) {
	n, p := policy(), resultPolicy()
	c, e := NewResultContract(n, p)
	if e != nil {
		t.Fatal(e)
	}
	oldGroup, oldActions := unitModel()
	if e = prepareGroups(oldGroup, n, config(n), 123); e != nil {
		t.Fatal(e)
	}
	b := config(n)
	b.Version, b.Results = 4, &p
	g, actions := unitModel()
	if e = prepareContractGroups(g, c, b, 123); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(*oldActions, *actions) || (*actions)[len(*actions)-1] != "unit/node/control/cgroup.procs=123" || b.Version != 4 || b.Results != &p {
		t.Fatal("expanded caps, altered ordering or downgraded actual config")
	}
	g, actions = unitModel()
	if prepareGroups(g, n, b, 123) == nil || len(*actions) != 0 {
		t.Fatal("old path adopted V4 or changed a group")
	}
}

func TestRetainedLaunchGroupMismatchRefusesBeforeWrites(t *testing.T) {
	c, e := NewResultContract(policy(), resultPolicy())
	if e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*firecracker.Config){
		"missing": func(b *firecracker.Config) { b.Results = nil },
		"bytes":   func(b *firecracker.Config) { b.Results.Bytes-- },
		"tenant":  func(b *firecracker.Config) { b.Results.TenantBytes-- },
		"records": func(b *firecracker.Config) { b.Results.Records-- },
		"version": func(b *firecracker.Config) { b.Version = 3 },
		"node":    func(b *firecracker.Config) { b.Node = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := resultPolicy()
			b := config(policy())
			b.Version, b.Results = 4, &p
			change(&b)
			g, actions := unitModel()
			if prepareContractGroups(g, c, b, 123) == nil || len(*actions) != 0 {
				t.Fatal("mutated group before complete contract match")
			}
		})
	}
}
