//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Synthetic mechanism controls, not hardware/PID1 acceptance. wait records the
// requested exact PID and NEVER calls a kernel wait or forks a host process.
func nodeLoadInitSynthetic() (*nodeLoadInit, nodeLoadInitIO, map[string][]byte, *[]int) {
	r := &nodeLoadInit{controller: 2, start: "123"}
	files := map[string][]byte{"/proc/2/stat": nodeLoadSyntheticStat(2, "managed", "S", "1")}
	for pid := 10; pid < 18; pid++ {
		p := "/proc/" + strconv.Itoa(pid)
		files[p+"/stat"] = nodeLoadSyntheticStat(pid, "firecracker", "Z", "1")
		files[p+"/status"] = []byte("Uid:\t400000\t400000\t400000\t400000\n")
		files[p+"/cgroup"] = []byte("0::/xandbox/instances/" + strings.Repeat("a", 64) + " (deleted)\n")
	}
	waited := []int{}
	ops := nodeLoadInitIO{
		read: func(path string) ([]byte, error) {
			if b, ok := files[path]; ok {
				return b, nil
			}
			return nil, os.ErrNotExist
		},
		list: func() ([]string, error) {
			return []string{"self", "1", "2", "10", "11", "12", "13", "14", "15", "16", "17"}, nil
		},
		wait: func(pid int) (int, error) {
			waited = append(waited, pid)
			delete(files, fmt.Sprintf("/proc/%d/stat", pid))
			return pid, nil
		},
	}
	return r, ops, files, &waited
}

func TestNodeLoadInitSyntheticReapsOnlyEightExactOwnedAdoptedZombies(t *testing.T) {
	r, ops, _, waited := nodeLoadInitSynthetic()
	n, e := r.sweepOwned(context.Background(), ops)
	if e != nil || n != 8 || len(*waited) != 8 {
		t.Fatal("exact synthetic waits missing", n, e)
	}
	for i, pid := range *waited {
		if pid != i+10 {
			t.Fatal("not an exact eligible PID")
		}
	}
	n, e = r.sweepOwned(context.Background(), ops)
	if e != nil || n != 0 || len(*waited) != 8 {
		t.Fatal("already reaped synthetic child was waited twice", n, e)
	}
}

func TestNodeLoadInitSyntheticNeverWaitsManagedLiveForeignOrAmbiguousChildren(t *testing.T) {
	for _, test := range []struct{ name, field, value string }{
		{"live", "stat", string(nodeLoadSyntheticStat(10, "firecracker", "S", "1"))},
		{"not_adopted", "stat", string(nodeLoadSyntheticStat(10, "firecracker", "Z", "9"))},
		{"helper", "stat", string(nodeLoadSyntheticStat(10, "xandbox-warden", "Z", "1"))},
		{"root", "status", "Uid: 0 0 0 0\n"},
		{"foreign_uid", "status", "Uid: 400004 400004 400004 400004\n"},
		{"uid_below", "status", "Uid: 399999 399999 399999 399999\n"},
		{"root_cgroup", "cgroup", "0::/\n"},
		{"control_cgroup", "cgroup", "0::/xandbox/control\n"},
		{"live_instance", "cgroup", "0::/xandbox/instances/" + strings.Repeat("a", 64) + "\n"},
		{"foreign_cgroup", "cgroup", "0::/other/instances/" + strings.Repeat("a", 64) + " (deleted)\n"},
		{"unknown_instance", "cgroup", "0::/xandbox/instances/not-an-id (deleted)\n"},
		{"nested_cgroup", "cgroup", "0::/xandbox/instances/" + strings.Repeat("a", 64) + "/child (deleted)\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, ops, files, waited := nodeLoadInitSynthetic()
			ops.list = func() ([]string, error) { return []string{"2", "10"}, nil }
			// Even if a managed child were otherwise made to match, exclude
			// its exact PID. controllerValid must also prevent waiting it.
			files["/proc/10/"+test.field] = []byte(test.value)
			n, e := r.sweepOwned(context.Background(), ops)
			if e != nil || n != 0 || len(*waited) != 0 {
				t.Fatal("non-owned candidate was waited", n, e)
			}
		})
	}
	r, ops, files, waited := nodeLoadInitSynthetic()
	files["/proc/2/stat"] = nodeLoadSyntheticStat(2, "firecracker", "Z", "1")
	files["/proc/2/status"] = files["/proc/10/status"]
	files["/proc/2/cgroup"] = files["/proc/10/cgroup"]
	if _, eligible, e := r.candidate(2, ops.read); e != nil || eligible || len(*waited) != 0 {
		t.Fatal("managed Cmd.Wait identity became an adopted candidate")
	}
	if _, e := r.sweepOwned(context.Background(), ops); e == nil || len(*waited) != 0 {
		t.Fatal("dead managed controller did not fence all waits")
	}
}

func TestNodeLoadInitSyntheticRevalidatesFullIdentityAndControllerBeforeExactWait(t *testing.T) {
	for _, field := range []string{"stat", "status", "cgroup", "controller"} {
		t.Run(field, func(t *testing.T) {
			r, ops, files, waited := nodeLoadInitSynthetic()
			ops.list = func() ([]string, error) { return []string{"10"}, nil }
			read := ops.read
			reads := 0
			target := "/proc/10/" + field
			if field == "controller" {
				target = "/proc/2/stat"
			}
			ops.read = func(path string) ([]byte, error) {
				if path == target {
					reads++
					if reads == 2 {
						switch field {
						case "stat":
							files[path] = []byte(strings.Replace(string(files[path]), " 123", " 124", 1))
						case "status":
							files[path] = []byte("Uid: 400001 400001 400001 400001\n")
						case "cgroup":
							files[path] = []byte(strings.ReplaceAll(string(files[path]), strings.Repeat("a", 64), strings.Repeat("b", 64)))
						case "controller":
							files[path] = nodeLoadSyntheticStat(2, "managed", "Z", "1")
						}
					}
				}
				return read(path)
			}
			if _, e := r.sweepOwned(context.Background(), ops); e == nil || len(*waited) != 0 {
				t.Fatal("changed ownership reached exact wait")
			}
		})
	}
}

func TestNodeLoadInitSyntheticBoundsErrorsAndNonblockingWaitCannotBecomeSuccess(t *testing.T) {
	for _, mode := range []string{"canceled", "oversize", "enumeration", "bad_stat", "bad_uid", "read", "no_child", "not_reaped", "wrong_pid", "controller_incarnation"} {
		t.Run(mode, func(t *testing.T) {
			r, ops, files, waited := nodeLoadInitSynthetic()
			ops.list = func() ([]string, error) { return []string{"10"}, nil }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "canceled":
				cancel()
			case "oversize":
				ops.list = func() ([]string, error) { return make([]string, nodeLoadProcLimit+1), nil }
			case "enumeration":
				ops.list = func() ([]string, error) { return nil, errors.New("private source error") }
			case "bad_stat":
				files["/proc/10/stat"] = []byte("invalid")
			case "bad_uid":
				files["/proc/10/status"] = []byte("invalid")
			case "read":
				delete(files, "/proc/10/cgroup")
			case "no_child":
				ops.wait = func(int) (int, error) { return 0, errors.New("ECHILD") }
			case "not_reaped":
				ops.wait = func(int) (int, error) { return 0, nil }
			case "wrong_pid":
				ops.wait = func(int) (int, error) { return 11, nil }
			case "controller_incarnation":
				r.start = "124"
			}
			n, e := r.sweepOwned(ctx, ops)
			if e == nil || n != 0 || len(*waited) != 0 {
				t.Fatal("bounded mechanism failure became success", n, e)
			}
		})
	}
}

func TestNodeLoadInitHostBoundaryAndCensusGateCancellation(t *testing.T) {
	n := &node{nodeLoad: true, nodeBudget: true, quotaDriver: true}
	ctx := context.Background()
	if n.startNodeLoadInit(ctx, make(chan struct{})) == nil || n.loadInit != nil {
		t.Fatal("reaper escaped owned PID1 guard")
	}
	if _, e := n.nodeLoadInitQuiesce(ctx); e == nil {
		t.Fatal("quiescent waits escaped owned PID1")
	}
	if _, e := nodeLoadInitOS().wait(1); e == nil {
		t.Fatal("OS exact wait escaped final PID1 guard")
	}
	gate := make(chan struct{}, 1)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if nodeLoadInitLock(canceled, gate) == nil {
		t.Fatal("canceled gate wait succeeded")
	}
	gate <- struct{}{}
	if nodeLoadInitLock(ctx, gate) != nil || len(gate) != 0 {
		t.Fatal("gate did not serialize census and reaping")
	}
	if nodeLoadInitLock(canceled, gate) == nil || len(gate) != 0 {
		t.Fatal("canceled waiter released somebody else's gate")
	}
	gate <- struct{}{}
	stats := nodeLoadInitStats{Active: true, Sweeps: 3, Reaped: 8}
	b, e := json.Marshal(stats)
	if e != nil || string(b) != `{"active":true,"sweeps":3,"reaped":8,"errors":0}` {
		t.Fatal("unexpected identity/error in aggregate init stats", e)
	}
	if nodeLoadInitPeriod != 250000000 {
		t.Fatal("init sweep frequency changed")
	}
}
