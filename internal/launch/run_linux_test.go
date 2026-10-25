//go:build linux

package launch

import (
	"strings"
	"testing"
)

func TestEveryCapabilitySetAndNNPRequired(t *testing.T) {
	good := "Uid:\t0 0 0 0\nCapInh:\t0000000000000000\nCapPrm:\t00000000feffffff\nCapEff:\t00000000feffffff\nCapBnd:\t00000000feffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1"
	if e := safeCapabilities(good); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		lines := strings.Split(good, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, key+":") {
				lines[i] = key + ":\t0000000001000000"
			}
		}
		if e := safeCapabilities(strings.Join(lines, "\n")); e == nil {
			t.Fatal("quota bypass allowed")
		}
	}
	for _, bad := range []string{strings.Replace(good, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), good + "\nCapAmb:\t0", strings.Replace(good, "CapBnd:\t00000000feffffff\n", "", 1), strings.Replace(good, "Uid:\t0 0 0 0", "Uid:\t0 1000 0 0", 1)} {
		if e := safeCapabilities(bad); e == nil {
			t.Fatal("invalid status accepted")
		}
	}
}
func TestFailureStageDoesNotRenderUnderlyingError(t *testing.T) {
	e := &failure{stage: "asset", cause: errPolicy}
	if FailureStage(e) != "asset" || strings.Contains(e.Error(), "asset") {
		t.Fatal("closed stage projection drift")
	}
}
