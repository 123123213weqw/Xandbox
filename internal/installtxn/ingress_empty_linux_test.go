//go:build linux

package installtxn

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRecoveryIngressEmptyEventsWholeSubtreeNotManagerPID(t *testing.T) {
	for _, raw := range []string{"populated 0\nfrozen 0\n", "frozen 0\npopulated 0\n"} {
		if e := parseIngressEmptyEvents([]byte(raw)); e != nil {
			t.Fatal("empty complete kernel report refused", e)
		}
	}
	for _, raw := range []string{"", "populated 0\n", "frozen 0\n", "populated 1\nfrozen 0\n", "populated 0\nfrozen 1\n", "populated 0\nfrozen 0", "populated 0\nfrozen 0\npopulated 0\n", "populated 0\nfrozen 0\nunknown 0\n", "populated 00\nfrozen 0\n", "populated 0\nfrozen 0\n\n", "populated 0\r\nfrozen 0\n", "populated 0\nfrozen 0\x00\n", strings.Repeat("x", maxIngressEvents+1)} {
		if parseIngressEmptyEvents([]byte(raw)) == nil {
			t.Fatal("nonempty/frozen/incomplete/unrecognized report accepted")
		}
	}
}
func TestRecoveryIngressEmptyRequiresRealCgroup2EvenWhenUnitAbsent(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "unit-absent", true: "fake-events"}[present], func(t *testing.T) {
			f, _, _ := fixture(t)
			if present {
				dir := f.root.Name() + ingressCgroupParent + "/" + IngressUnit
				if e := os.MkdirAll(dir, 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(dir+"/cgroup.events", []byte("populated 0\nfrozen 0\n"), 0444); e != nil {
					t.Fatal(e)
				}
			}
			if e := f.ingressEmpty(); !errors.Is(e, ErrPlatform) {
				t.Fatal("ordinary shadow filesystem accepted as cgroup absence/emptiness", e)
			}
		})
	}
}
