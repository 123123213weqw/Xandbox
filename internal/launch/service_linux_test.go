//go:build linux

package launch

import (
	"fmt"
	"strings"
	"testing"
)

func ingressModel() (*model, *[]string) {
	g, a := unitModel()
	g.children = map[string]*model{}
	g.values["cgroup.procs"] = "123"
	g.values["memory.oom.group"] = "1"
	return g, a
}
func TestServiceEnvelopeReadOnlyAndRejectsEachKernelDrift(t *testing.T) {
	g, a := ingressModel()
	if e := checkServiceEnvelope(g, "253:0", policy().Parent, true, 123); e != nil {
		t.Fatal(e)
	}
	if len(*a) != 0 {
		t.Fatal("read-only check wrote cgroups")
	}
	for _, key := range []string{"cgroup.type", "cgroup.procs", "cgroup.subtree_control", "memory.oom.group", "memory.max", "memory.swap.max", "pids.max", "cpu.max", "io.max"} {
		g, a := ingressModel()
		g.values[key] = "drift"
		if checkServiceEnvelope(g, "253:0", policy().Parent, true, 123) == nil {
			t.Fatal("drift accepted", key)
		}
		if len(*a) != 0 {
			t.Fatal("check repaired kernel state")
		}
	}
	for _, name := range []string{".control", "bootstrap", "node", "foreign"} {
		g, a := ingressModel()
		g.children[name] = newModel(name, a)
		if checkServiceEnvelope(g, "253:0", policy().Parent, true, 123) == nil {
			t.Fatal("adopted child")
		}
		if len(*a) != 0 {
			t.Fatal("check changed child")
		}
	}
	g, a = ingressModel()
	g.values["io.max"] += "\n8:0 rbps=max"
	if checkServiceEnvelope(g, "253:0", policy().Parent, true, 123) == nil {
		t.Fatal("extra IO device accepted")
	}
	g, a = unitModel()
	if e := checkServiceEnvelope(g, "253:0", policy().Parent, false, 123); e != nil {
		t.Fatal(e)
	}
	if len(*a) != 0 {
		t.Fatal("daemon parent mutated")
	}
}
func TestExactServiceCapabilitiesIncludesAllObservedFields(t *testing.T) {
	const mask = uint64(1<<6 | 1<<7 | 1<<18)
	good := fmt.Sprintf("Uid:\t0 0 0 0\nGid:\t0 0 0 0\nNoNewPrivs:\t1\nCapInh:\t0\nCapAmb:\t0\nCapEff:\t%x\nCapPrm:\t%x\nCapBnd:\t%x", mask, mask, mask)
	if e := exactServiceCapabilities(good, mask); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"Uid", "Gid", "NoNewPrivs", "CapInh", "CapAmb", "CapEff", "CapPrm", "CapBnd"} {
		lines := strings.Split(good, "\n")
		var changed, removed []string
		for _, line := range lines {
			if strings.HasPrefix(line, key+":") {
				changed = append(changed, key+":\t1000000")
			} else {
				changed = append(changed, line)
				removed = append(removed, line)
			}
		}
		for _, bad := range []string{strings.Join(changed, "\n"), strings.Join(removed, "\n"), good + "\n" + key + ":\t0"} {
			if exactServiceCapabilities(bad, mask) == nil {
				t.Fatal("capability drift accepted", key)
			}
		}
	}
}
