package serviceready

import (
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
)

// Pure byte comparisons through the SAME helper called by actual mainProof;
// not proof of a real daemon PID, health, backend construction or deployment.
func TestRetainedLaunchReadinessUsesCompleteExplicitProcessArguments(t *testing.T) {
	_, n := policies()
	c, e := launch.NewResultContract(n, firecracker.ResultPolicy{Version: 1, Bytes: 8 << 20, TenantBytes: 2 << 20, Records: 32})
	if e != nil {
		t.Fatal(e)
	}
	expected := c.Arguments()
	raw := strings.Join(expected, "\x00") + "\x00"
	legacy := strings.Join(n.Arguments(), "\x00") + "\x00"
	if !processArgumentsMatch([]byte(raw), expected) || !processArgumentsMatch([]byte(legacy), n.Arguments()) {
		t.Fatal("exact own argv rejected")
	}
	for name, actual := range map[string]string{
		"legacy-missing-retention": legacy,
		"changed-bytes":            strings.Replace(raw, "8388608", "8388609", 1),
		"changed-tenant":           strings.Replace(raw, "2097152", "2097151", 1),
		"changed-records":          strings.TrimSuffix(raw, "32\x00") + "33\x00",
		"extra-argument":           raw + "-metrics\x00",
		"missing-final-nul":        strings.TrimSuffix(raw, "\x00"),
		"extra-final-nul":          raw + "\x00",
		"source-config":            strings.Replace(raw, n.InputDir+"/backend.json", n.Backend.Path, 1),
		"shell":                    "/bin/sh\x00-c\x00" + raw,
	} {
		t.Run(name, func(t *testing.T) {
			if processArgumentsMatch([]byte(actual), expected) {
				t.Fatal("mismatched full process argv accepted")
			}
		})
	}
	if processArgumentsMatch([]byte(raw), n.Arguments()) || processArgumentsMatch([]byte("\x00"), nil) {
		t.Fatal("version conflation or empty process contract")
	}
}
