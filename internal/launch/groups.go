package launch

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
)

// group is an anchored owned cgroup directory, not an arbitrary filesystem path.
// The mock implementations test ordering only; actual cgroup2 is tested in L1.
type group interface {
	Read(string) (string, error)
	Write(string, string) error
	Children() ([]string, error)
	Open(string) (group, error)
	Mkdir(string) (group, error)
	Close() error
}

func sameWords(a, b string) bool {
	x, y := strings.Fields(a), strings.Fields(b)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, " ") == strings.Join(y, " ") && len(x) == len(y)
}
func expect(g group, k, w string) error {
	v, e := g.Read(k)
	if e != nil {
		return e
	}
	if v != w {
		return errors.New("resource readback mismatch")
	}
	return nil
}
func writeExact(g group, k, v string) error {
	if e := g.Write(k, v); e != nil {
		return e
	}
	return expect(g, k, v)
}
func checkIO(g group, want string) error {
	got, e := g.Read("io.max")
	if e != nil {
		return e
	}
	a, b := strings.Fields(got), strings.Fields(want)
	if strings.Count(got, "\n") != 0 || len(a) != 5 || len(b) != 5 || a[0] != b[0] || !sameWords(got, want) {
		return errors.New("IO readback mismatch")
	}
	return nil
}
func enable(g group) error {
	if e := expect(g, "cgroup.type", "domain"); e != nil {
		return e
	}
	if e := expect(g, "cgroup.procs", ""); e != nil {
		return e
	}
	have, e := g.Read("cgroup.controllers")
	if e != nil {
		return e
	}
	active, e := g.Read("cgroup.subtree_control")
	if e != nil {
		return e
	}
	contains := func(raw, key string) bool {
		for _, v := range strings.Fields(raw) {
			if key == v {
				return true
			}
		}
		return false
	}
	var missing []string
	for _, key := range []string{"cpu", "io", "memory", "pids"} {
		if !contains(have, key) {
			return errors.New("missing delegated controller")
		}
		if !contains(active, key) {
			missing = append(missing, "+"+key)
		}
	}
	if len(missing) > 0 {
		if e = g.Write("cgroup.subtree_control", strings.Join(missing, " ")); e != nil {
			return e
		}
	}
	active, e = g.Read("cgroup.subtree_control")
	if e != nil {
		return e
	}
	for _, key := range []string{"cpu", "io", "memory", "pids"} {
		if !contains(active, key) {
			return errors.New("controller activation mismatch")
		}
	}
	return nil
}
func prepareGroups(unit group, m Manifest, c firecracker.Config, pid int) error {
	if e := m.checkBackend(c); e != nil {
		return e
	}
	if e := expect(unit, "cgroup.type", "domain"); e != nil {
		return e
	}
	if e := expect(unit, "cgroup.procs", ""); e != nil {
		return e
	}
	children, e := unit.Children()
	if e != nil {
		return e
	}
	bootstrapFound := false
	for _, name := range children {
		if name == "bootstrap" {
			bootstrapFound = true
		} else if name != ".control" {
			return errors.New("unknown or already initialized unit subtree")
		}
	}
	if !bootstrapFound {
		return errors.New("missing manager bootstrap subgroup")
	}
	bootstrap, e := unit.Open("bootstrap")
	if e != nil {
		return e
	}
	defer bootstrap.Close()
	if e = expect(bootstrap, "cgroup.procs", strconv.Itoa(pid)); e != nil {
		return e
	}
	for _, v := range []struct{ k, w string }{{"memory.max", fmt.Sprint(m.Parent.MemoryMax)}, {"memory.swap.max", "0"}, {"pids.max", fmt.Sprint(m.Parent.PidsMax)}, {"cpu.max", fmt.Sprintf("%d 100000", m.Parent.CPUQuota)}} {
		if e = expect(unit, v.k, v.w); e != nil {
			return e
		}
	}
	if e = checkIO(unit, ioLine(c.IO.Device, m.Parent.IOBytesPerSecond, m.Parent.IOOperationsPerSecond)); e != nil {
		return e
	}
	if e = enable(unit); e != nil {
		return e
	}
	node, e := unit.Mkdir("node")
	if e != nil {
		return e
	}
	defer node.Close()
	control, e := node.Mkdir("control")
	if e != nil {
		return e
	}
	defer control.Close()
	instances, e := node.Mkdir("instances")
	if e != nil {
		return e
	}
	defer instances.Close()
	n := c.Node
	for _, v := range []struct{ k, w string }{{"memory.max", fmt.Sprint(n.MemoryMax)}, {"memory.swap.max", "0"}, {"pids.max", fmt.Sprint(n.PidsMax)}, {"cpu.max", fmt.Sprintf("%d 100000", n.CPUQuota)}} {
		if e = writeExact(node, v.k, v.w); e != nil {
			return e
		}
	}
	if e = node.Write("io.max", ioLine(c.IO.Device, n.IOBytesPerSecond, n.IOOperationsPerSecond)); e != nil {
		return e
	}
	if e = checkIO(node, ioLine(c.IO.Device, n.IOBytesPerSecond, n.IOOperationsPerSecond)); e != nil {
		return e
	}
	if e = enable(node); e != nil {
		return e
	}
	for _, v := range []struct{ k, w string }{{"memory.max", fmt.Sprint(n.ControllerMemoryMax)}, {"memory.swap.max", "0"}, {"memory.oom.group", "1"}, {"pids.max", fmt.Sprint(n.ControllerPidsMax)}} {
		if e = writeExact(control, v.k, v.w); e != nil {
			return e
		}
	}
	for _, v := range []struct{ k, w string }{{"memory.max", fmt.Sprint(uint64(n.MaxInstances) * (768 << 20))}, {"memory.swap.max", "0"}, {"memory.oom.group", "1"}, {"pids.max", fmt.Sprint(uint64(n.MaxInstances) * 64)}, {"cpu.max", fmt.Sprintf("%d 100000", uint64(n.MaxInstances)*200000)}} {
		if e = writeExact(instances, v.k, v.w); e != nil {
			return e
		}
	}
	if e = enable(instances); e != nil {
		return e
	}
	// The only migration is the launcher process itself, before daemon exec.
	// Writing cgroup.procs moves its whole thread group, including Go threads.
	return control.Write("cgroup.procs", strconv.Itoa(pid))
}
