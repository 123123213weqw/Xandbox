//go:build linux

package installtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func observationBytes(unit, load, active, enabled string, pid int) []byte {
	fragment := ""
	if load == "loaded" {
		fragment = UnitDir + "/" + unit
	}
	return []byte("MainPID=" + stringInt(pid) + "\nLoadState=" + load + "\nActiveState=" + active + "\nFragmentPath=" + fragment + "\nDropInPaths=\nUnitFileState=" + enabled + "\n")
}
func stringInt(v int) string { return strconv.Itoa(v) }
func TestManagerParsesExactObservedContractAndRefusesUnknown(t *testing.T) {
	raw := observationBytes(MainUnit, "not-found", "inactive", "", 0)
	o, e := parseObservation(raw)
	if e != nil || o.load != "not-found" || o.pid != 0 {
		t.Fatal(o, e)
	}
	for _, bad := range [][]byte{append(raw, []byte("MainPID=0\n")...), bytes.ReplaceAll(raw, []byte("MainPID=0"), []byte("MainPID=00")), bytes.ReplaceAll(raw, []byte("MainPID=0\n"), nil), append(raw, []byte("credential=do-not-export\n")...), bytes.Repeat([]byte("x"), 16385)} {
		if _, e := parseObservation(bad); e == nil {
			t.Fatal("invalid manager view accepted")
		}
	}
}
func TestManagerReconcileIdempotentStartAndRealLinkChecks(t *testing.T) {
	f, _, _ := fixture(t)
	phase := 0
	commands := []string{}
	run := func(_ context.Context, args []string) ([]byte, error) {
		commands = append(commands, strings.Join(args, " "))
		switch args[0] {
		case "show":
			unit := args[len(args)-1]
			if phase == 0 {
				return observationBytes(unit, "not-found", "inactive", "", 0), nil
			}
			if phase < 3 {
				return observationBytes(unit, "loaded", "inactive", "disabled", 0), nil
			}
			return observationBytes(unit, "loaded", "active", "enabled", 123), nil
		case "daemon-reload":
			phase = 1
		case "enable":
			phase = 2
			for _, dir := range []string{UnitDir + "/multi-user.target.wants", UnitDir + "/" + MainUnit + ".wants"} {
				if e := os.MkdirAll(f.root.Name()+dir, 0700); e != nil {
					t.Fatal(e)
				}
			}
			os.Symlink("../"+MainUnit, f.root.Name()+UnitDir+"/multi-user.target.wants/"+MainUnit)
			os.Symlink("../"+IngressUnit, f.root.Name()+UnitDir+"/"+MainUnit+".wants/"+IngressUnit)
		case "start":
			if args[1] != MainUnit || phase != 2 {
				t.Fatal("wrong start order")
			}
			phase = 3
		default:
			t.Fatal("unexpected operation", args)
		}
		return nil, nil
	}
	m := systemManager{f, run}
	if e := m.fresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := m.reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	if yes, e := m.current(context.Background()); e != nil || !yes {
		t.Fatal(yes, e)
	}
	if e := m.reconcile(context.Background()); e != nil {
		t.Fatal("idempotent replay", e)
	}
	starts := 0
	for _, v := range commands {
		if v == "start "+MainUnit {
			starts++
		}
	}
	if starts != 2 {
		t.Fatal("expected idempotent start, not restart", starts)
	}
	for _, v := range commands {
		for _, bad := range []string{"restart", "stop", "resume", "reset-failed", "daemon-reexec"} {
			if strings.HasPrefix(v, bad) {
				t.Fatal("hidden destructive manager operation", v)
			}
		}
	}
	link := f.root.Name() + UnitDir + "/" + MainUnit + ".wants/" + IngressUnit
	os.Remove(link)
	os.Symlink("/foreign-unit", link)
	if _, e := m.current(context.Background()); e == nil {
		t.Fatal("foreign enablement adopted")
	}
}
func TestManagerRefusesForeignFragmentDropinsAndUnconfirmedOutcome(t *testing.T) {
	f, _, _ := fixture(t)
	for _, bad := range []string{"foreign", "dropin", "transport"} {
		t.Run(bad, func(t *testing.T) {
			calls := 0
			m := systemManager{f, func(_ context.Context, args []string) ([]byte, error) {
				calls++
				if args[0] == "daemon-reload" {
					return nil, nil
				}
				if bad == "transport" {
					return nil, errors.New("unconfirmed manager receipt")
				}
				raw := observationBytes(MainUnit, "loaded", "inactive", "disabled", 0)
				if bad == "foreign" {
					raw = bytes.ReplaceAll(raw, []byte(UnitDir+"/"+MainUnit), []byte("/usr/lib/systemd/system/foreign.service"))
				} else {
					raw = bytes.ReplaceAll(raw, []byte("DropInPaths=\n"), []byte("DropInPaths=/etc/foreign.conf\n"))
				}
				return raw, nil
			}}
			if e := m.reconcile(context.Background()); e == nil {
				t.Fatal("foreign state accepted")
			}
			if calls > 2 {
				t.Fatal("continued to enable/start after refusal")
			}
		})
	}
}
func TestBoundedManagerWriterNeverExportsRawOverflow(t *testing.T) {
	b := &limitedBuffer{limit: 3}
	if _, e := b.Write([]byte("abc")); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Write([]byte("private-overflow")); e == nil || b.String() != "abc" {
		t.Fatal("unbounded writer")
	}
}
