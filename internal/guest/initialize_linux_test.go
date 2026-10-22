//go:build linux

package guest

import (
	"github.com/123123213weqw/Xandbox/internal/guestinit"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"os"
	"strings"
	"testing"
)

func TestPristineInitializerRefusesOrdinaryHost(t *testing.T) {
	// Never create a guest marker or alter host devices/clocks to exercise tests.
	if _, e := os.Stat("/etc/xandbox-guest"); e == nil {
		t.Skip("host refusal test requires a normal non-guest environment")
	}
	before, _ := os.Stat(initDir)
	if _, e := PristineBoot(); e == nil {
		t.Fatal("normal host accepted")
	}
	r, e := guestinit.NewRequest(sandbox.Ref{ID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)})
	if e != nil {
		t.Fatal(e)
	}
	defer r.WipeEntropy()
	if e = InitializeAndExec(r); e == nil {
		t.Fatal("host initializer succeeded")
	}
	after, _ := os.Stat(initDir)
	if before == nil && after != nil {
		t.Fatal("host initialization directory created")
	}
	if _, _, _, _, e := NewInitializedExecutor(); e == nil {
		t.Fatal("normal host treated as initialized guest")
	}
}
