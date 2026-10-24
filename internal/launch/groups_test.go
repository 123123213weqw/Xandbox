package launch

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type model struct {
	values   map[string]string
	children map[string]*model
	path     string
	actions  *[]string
	fail     string
}

func newModel(path string, actions *[]string) *model {
	return &model{map[string]string{"cgroup.type": "domain", "cgroup.procs": "", "cgroup.controllers": "cpu io memory pids", "cgroup.subtree_control": ""}, map[string]*model{}, path, actions, ""}
}
func (m *model) Read(k string) (string, error) {
	v, ok := m.values[k]
	if !ok {
		return "", errors.New("missing model interface")
	}
	return v, nil
}
func (m *model) Write(k, v string) error {
	*m.actions = append(*m.actions, m.path+"/"+k+"="+v)
	if m.fail == k {
		return errors.New("injected write refusal")
	}
	if k == "cgroup.subtree_control" {
		v = strings.ReplaceAll(v, "+", "")
	}
	m.values[k] = v
	return nil
}
func (m *model) Children() ([]string, error) {
	var names []string
	for n := range m.children {
		names = append(names, n)
	}
	return names, nil
}
func (m *model) Open(n string) (group, error) {
	g, ok := m.children[n]
	if !ok {
		return nil, errors.New("missing model child")
	}
	return g, nil
}
func (m *model) Mkdir(n string) (group, error) {
	if _, ok := m.children[n]; ok {
		return nil, errors.New("exclusive mkdir")
	}
	g := newModel(m.path+"/"+n, m.actions)
	m.children[n] = g
	*m.actions = append(*m.actions, "mkdir:"+g.path)
	return g, nil
}
func (m *model) Close() error { return nil }
func unitModel() (*model, *[]string) {
	actions := []string{}
	g := newModel("unit", &actions)
	m := policy()
	g.values["memory.max"] = fmt.Sprint(m.Parent.MemoryMax)
	g.values["memory.swap.max"] = "0"
	g.values["pids.max"] = fmt.Sprint(m.Parent.PidsMax)
	g.values["cpu.max"] = "800000 100000"
	g.values["io.max"] = ioLine("253:0", m.Parent.IOBytesPerSecond, m.Parent.IOOperationsPerSecond)
	b := newModel("unit/bootstrap", &actions)
	b.values["cgroup.procs"] = "123"
	g.children["bootstrap"] = b
	return g, &actions
}
func TestSetupMigratesOnlySelfLastAndKeepsControlLimits(t *testing.T) {
	g, actions := unitModel()
	m := policy()
	if e := prepareGroups(g, m, config(m), 123); e != nil {
		t.Fatal(e)
	}
	last := (*actions)[len(*actions)-1]
	if last != "unit/node/control/cgroup.procs=123" {
		t.Fatal(last)
	}
	node := g.children["node"]
	if len(node.children) != 2 || node.children["control"].values["memory.max"] != "1073741824" || node.children["instances"].values["pids.max"] != "256" {
		t.Fatal("planning drift")
	}
	for _, line := range *actions {
		if strings.Contains(line, "cgroup.procs=") && line != last {
			t.Fatal("unexpected migration")
		}
	}
}
func TestUnknownOrAlreadyInitializedSubtreeRefusedBeforeWrites(t *testing.T) {
	for _, name := range []string{"node", "foreign"} {
		g, actions := unitModel()
		g.children[name] = newModel("unit/"+name, actions)
		if e := prepareGroups(g, policy(), config(policy()), 123); e == nil {
			t.Fatal("adopted subtree")
		}
		if len(*actions) != 0 {
			t.Fatal("mutation before ownership refusal")
		}
	}
}
func TestManagerDriftAndForeignBootstrapRefusedBeforeWrites(t *testing.T) {
	for _, change := range []func(*model){func(g *model) { g.values["memory.max"] = "max" }, func(g *model) { g.values["pids.max"] = "513" }, func(g *model) { g.values["memory.swap.max"] = "max" }, func(g *model) { g.values["io.max"] += "\n8:0 rbps=max" }, func(g *model) { g.children["bootstrap"].values["cgroup.procs"] = "123\n456" }, func(g *model) { g.values["cgroup.procs"] = "123" }} {
		g, a := unitModel()
		change(g)
		if e := prepareGroups(g, policy(), config(policy()), 123); e == nil {
			t.Fatal("manager drift accepted")
		}
		if len(*a) != 0 {
			t.Fatal("mutated before drift refusal")
		}
	}
}
func TestMissingControllerAndWriteFailureDoNotMigrate(t *testing.T) {
	g, a := unitModel()
	g.values["cgroup.controllers"] = "cpu memory pids"
	if e := prepareGroups(g, policy(), config(policy()), 123); e == nil {
		t.Fatal("io missing accepted")
	}
	if len(*a) != 0 {
		t.Fatal("mutation before delegation check")
	}
	g, a = unitModel()
	g.fail = "cgroup.subtree_control"
	if e := prepareGroups(g, policy(), config(policy()), 123); e == nil {
		t.Fatal("write failure ignored")
	}
	for _, line := range *a {
		if strings.Contains(line, "cgroup.procs=") {
			t.Fatal("migrated after failure")
		}
	}
}
func TestIOReadbackAllowsOnlyReorderingNotExtraOrDuplicateValues(t *testing.T) {
	g, _ := unitModel()
	want := g.values["io.max"]
	fields := strings.Fields(want)
	g.values["io.max"] = strings.Join([]string{fields[0], fields[4], fields[3], fields[2], fields[1]}, " ")
	if e := checkIO(g, want); e != nil {
		t.Fatal(e)
	}
	g.values["io.max"] += " " + fields[1]
	if e := checkIO(g, want); e == nil {
		t.Fatal("duplicate accepted")
	}
}
