package guest

import (
	"strings"
	"testing"
)

func TestColdAndPristineBootModesAreDisjoint(t *testing.T) {
	cold := "console=ttyS0 xandbox.guest=1 xandbox.id=" + strings.Repeat("a", 32) + " xandbox.generation=" + strings.Repeat("b", 32)
	if ref, p, e := parseBoot(cold); e != nil || p || ref.ID == "" {
		t.Fatal("cold mode rejected")
	}
	pristine := "xandbox.guest=1 xandbox.pristine=1"
	if ref, p, e := parseBoot(pristine); e != nil || !p || ref.ID != "" {
		t.Fatal("pristine mode rejected")
	}
	for _, bad := range []string{cold + " xandbox.pristine=1", pristine + " xandbox.id=", pristine + " xandbox.pristine=1", cold + " xandbox.id=" + strings.Repeat("c", 32), "xandbox.pristine=1", "xandbox.guest=1", pristine + " xandbox.guest=0"} {
		if _, _, e := parseBoot(bad); e == nil {
			t.Fatal("ambiguous boot accepted")
		}
	}
}
