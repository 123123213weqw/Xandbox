//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func managerLinks(t *testing.T, f *filesystem) {
	t.Helper()
	for _, d := range []string{UnitDir + "/multi-user.target.wants", UnitDir + "/" + MainUnit + ".wants"} {
		if e := os.MkdirAll(f.root.Name()+d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink("../"+MainUnit, f.root.Name()+UnitDir+"/multi-user.target.wants/"+MainUnit); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("../"+IngressUnit, f.root.Name()+UnitDir+"/"+MainUnit+".wants/"+IngressUnit); e != nil {
		t.Fatal(e)
	}
}
func TestRecoveryManagerStopsOnlyIngressAndPinsMainThroughFinalCallback(t *testing.T) {
	for _, kind := range []string{"active", "already-stopped", "inactive-main", "foreign-main", "foreign-ingress", "foreign-link", "stop-error", "not-stopped", "main-change-after-stop", "main-change-after-work", "work-error"} {
		t.Run(kind, func(t *testing.T) {
			f, _, _ := fixture(t)
			managerLinks(t, f)
			if kind == "foreign-link" {
				p := f.root.Name() + UnitDir + "/" + MainUnit + ".wants/" + IngressUnit
				os.Remove(p)
				if e := os.Symlink("/foreign", p); e != nil {
					t.Fatal(e)
				}
			}
			stopped, worked := false, false
			var mutations []string
			m := systemManager{f, func(_ context.Context, args []string) ([]byte, error) {
				if args[0] == "show" {
					u := args[len(args)-1]
					state, pid := "active", os.Getpid()
					if u == MainUnit && kind == "inactive-main" {
						state, pid = "inactive", 0
					}
					if u == IngressUnit && (stopped || kind == "already-stopped") {
						state, pid = "inactive", 0
					}
					if u == IngressUnit && kind == "not-stopped" {
						state, pid = "active", os.Getpid()
					}
					if u == MainUnit && ((stopped && kind == "main-change-after-stop") || (worked && kind == "main-change-after-work")) {
						pid++
					}
					raw := observationBytes(u, "loaded", state, "enabled", pid)
					if (u == MainUnit && kind == "foreign-main") || (u == IngressUnit && kind == "foreign-ingress") {
						raw = []byte(strings.ReplaceAll(string(raw), "DropInPaths=\n", "DropInPaths=/foreign\n"))
					}
					return raw, nil
				}
				mutations = append(mutations, strings.Join(args, " "))
				if strings.Join(args, " ") != "--job-mode=ignore-dependencies stop "+IngressUnit {
					t.Fatal("unfixed/main mutation", args)
				}
				if kind == "stop-error" {
					return nil, interrupted
				}
				stopped = true
				return nil, nil
			}}
			e := m.maintainIngress(context.Background(), func() error {
				worked = true
				if kind == "work-error" {
					return interrupted
				}
				return nil
			})
			wantOK := kind == "active" || kind == "already-stopped"
			if (e == nil) != wantOK {
				t.Fatal("wrong maintenance result", kind, e)
			}
			if kind == "work-error" && !errors.Is(e, interrupted) {
				t.Fatal("work error lost")
			}
			if kind == "inactive-main" || kind == "foreign-main" || kind == "foreign-ingress" || kind == "foreign-link" {
				if worked || len(mutations) != 0 {
					t.Fatal("unsafe precondition reached stop/work")
				}
			}
			if kind == "stop-error" || kind == "not-stopped" || kind == "main-change-after-stop" {
				if worked {
					t.Fatal("work before stopped/same-main proof")
				}
			}
			if kind == "already-stopped" && len(mutations) != 0 {
				t.Fatal("unneeded destructive command")
			}
		})
	}
}
