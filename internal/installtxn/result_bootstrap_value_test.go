package installtxn

import (
	"bytes"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/ingresslaunch"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/serviceready"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"strings"
	"testing"
)

func resultWireSeed() resultTransaction {
	old := transactionValueSeed(2)
	return resultTransaction{Version: 2, Revision: old.Revision, RequestID: old.RequestID, Plan: old.Plan, Release: old.Release, Files: old.Files}
}
func TestResultBootstrapWireIsExplicitAndOldReaderStaysClosed(t *testing.T) {
	base := resultWireSeed()
	raw := encode(base)
	if !validResultTransaction(base) {
		t.Fatal("new seed")
	}
	if _, e := decodeTransactionBytes(raw); e == nil {
		t.Fatal("old reader accepted new version")
	}
	if got, e := decodeResultTransaction(raw); e != nil || !bytes.Equal(encode(got), raw) {
		t.Fatal(got, e)
	}
	for _, name := range []string{"legacy", "plan-legacy", "revision", "request", "unknown", "duplicate", "folded", "whitespace", "no-lf", "trailing", "missing-file", "wrong-mode", "artifact", "oversize"} {
		t.Run(name, func(t *testing.T) {
			q := resultWireSeed()
			var data []byte
			switch name {
			case "legacy":
				q.Version = 1
			case "plan-legacy":
				q.Plan.Version = 1
			case "revision":
				q.Revision = 2
			case "request":
				q.RequestID = strings.Repeat("A", 32)
			case "missing-file":
				q.Files = q.Files[:len(q.Files)-1]
			case "wrong-mode":
				q.Files[0].Mode = 0777
			case "artifact":
				q.Release.Files[0].SHA256 = strings.Repeat("e", 64)
			}
			data = encode(q)
			switch name {
			case "unknown":
				data = append([]byte(`{"unknown":0,`), data[1:]...)
			case "duplicate":
				data = append([]byte(`{"version":2,`), data[1:]...)
			case "folded":
				data = bytes.Replace(data, []byte(`"version":2`), []byte(`"Version":2`), 1)
			case "whitespace":
				data = append([]byte(" "), data...)
			case "no-lf":
				data = bytes.TrimSuffix(data, []byte("\n"))
			case "trailing":
				data = append(data, []byte("{}")...)
			case "oversize":
				data = bytes.Repeat([]byte(" "), 65537)
			}
			before := append([]byte(nil), data...)
			if _, e := decodeResultTransaction(data); e == nil || !bytes.Equal(before, data) {
				t.Fatal("invalid or mutated new wire", name, e)
			}
		})
	}
}
func TestResultBootstrapRenderPinsActualV2BytesWithoutGrowingEnvelopes(t *testing.T) {
	tx := resultWireSeed()
	art, e := descriptor(tx.Release)
	if e != nil {
		t.Fatal(e)
	}
	policy := firecracker.ResultPolicy{Version: 1, Bytes: 1 << 20, TenantBytes: 1 << 19, Records: 10}
	generated, e := renderResults(tx.Plan, "1:1", art, policy)
	if e != nil {
		t.Fatal(e)
	}
	c, e := launch.DecodeContract(generated[launchPath])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = launch.Decode(generated[launchPath]); e == nil {
		t.Fatal("V2 line was legacy")
	}
	var g ingresslaunch.Manifest
	var ready serviceready.Manifest
	if e = strictjson.Decode(generated[ingressPath], &g); e != nil {
		t.Fatal(e)
	}
	if e = strictjson.Decode(generated[readyPath], &ready); e != nil {
		t.Fatal(e)
	}
	if g.NodeLaunch.SHA256 != digest(generated[launchPath]) || ready.NodeLaunch != g.NodeLaunch || g.Ingress != tx.Plan.Ingress || g.Reserve != tx.Plan.Reserve || g.Capacity != tx.Plan.Capacity || c.Node().Parent != tx.Plan.Parent {
		t.Fatal("V2 bytes/envelopes not joined")
	}
	main := string(generated[UnitDir+"/"+MainUnit])
	if strings.Count(main, "ExecStartPre="+SelfPath+" verify-results\n") != 1 || strings.Contains(main, " verify\n") {
		t.Fatal("wrong versioned startup gate")
	}
	args := strings.Join(c.Arguments(), " ")
	if !strings.Contains(args, "-result-bytes 1048576 -result-tenant-bytes 524288 -result-records 10") {
		t.Fatal("missing explicit retention", args)
	}
	for _, bad := range []firecracker.ResultPolicy{{}, {Version: 1, Bytes: 1, TenantBytes: 2, Records: 1}, {Version: 2, Bytes: 1024, TenantBytes: 1024, Records: 1}} {
		if _, e = renderResults(tx.Plan, "1:1", art, bad); e == nil {
			t.Fatal("invalid result opt-in")
		}
	}
}
