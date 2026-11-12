//go:build linux

package installtxn

import (
	"crypto/ed25519"
	"os"
	"reflect"
	"sort"
	"testing"
)

// Independent owned signature fixture. Structural ELF bytes are never executed
// and contain no Go build/reader ABI or state-budget contract.
func imageDiskOn(t *testing.T, f *filesystem) (*programDiskFixture, ed25519.PrivateKey) {
	t.Helper()
	policy, cert, key, _ := programApprovalFixture(t)
	b := imageSectionsFixture()
	for i := range cert.Claim.Programs {
		cert.Claim.Programs[i].SHA256, cert.Claim.Programs[i].Bytes = digest(b), int64(len(b))
	}
	programApprovalSign(t, &cert, key, "Xandbox runtime program approval v1\x00")
	for _, dir := range []string{"/etc", runtimeProgramCertificateRoot, "/program-image-test-only"} {
		if e := os.MkdirAll(f.root.Name()+dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	x := &programDiskFixture{f: f, policy: policy, cert: cert, certificate: runtimeProgramCertificateRoot + "/" + digest(programApprovalWire(t, cert.Claim.Programs)) + ".json"}
	for i, row := range []struct{ path, role string }{
		{SelfPath, "installer"}, {childRoot + "/gateway", "gateway"},
		{rolePath("daemon"), "daemon"}, {rolePath("gateway"), "gateway"},
		{rolePath("ingress"), "ingress"}, {rolePath("launcher"), "launcher"},
		{rolePath("node"), "node"}, {rolePath("ready"), "ready"}, {rolePath("template"), "template"},
	} {
		path := f.root.Name() + "/program-image-test-only/" + row.role + string(rune('a'+i))
		// Independently owned originals, including two identical gateway copies;
		// no source is reopened by production validation.
		if e := os.WriteFile(path, b, 0400); e != nil {
			t.Fatal(e)
		}
		in, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { in.Close() })
		x.inputs = append(x.inputs, runtimeProgramInput{File{Path: row.path, SHA256: digest(b), Bytes: int64(len(b)), Mode: 0555}, in})
	}
	sort.Slice(x.inputs, func(i, j int) bool { return x.inputs[i].file.Path < x.inputs[j].file.Path })
	if e := os.WriteFile(f.root.Name()+runtimeProgramAuthorityPath, programApprovalWire(t, policy), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(f.root.Name()+x.certificate, programApprovalWire(t, cert), 0600); e != nil {
		t.Fatal(e)
	}
	return x, key
}

func TestRuntimeScopeProgramImagesOriginalStopRevocationRenewalAndRetirement(t *testing.T) {
	// ONE authentic owned V2 actor/Stop/original FD lifecycle. All kernel and
	// backend positives remain MODELS, and signed structural ELFs are not run.
	x, s, p, _ := resultsStateModel(t, false)
	fixture, key := imageDiskOn(t, x.f)
	ctx, cancel := workStopContext(t)
	defer cancel()
	base, operation := digest(encode(x.tx)), runtimeReq("b")
	if (*runtimeProgramApproval)(nil).validateNativePrograms(ctx) == nil || (&runtimeProgramApproval{}).validateNativePrograms(ctx) == nil {
		t.Fatal("nil/zero report acquired native program validation")
	}
	a, e := s.approveRuntimePrograms(ctx, base, operation, p, fixture.inputs)
	if e != nil {
		t.Fatal(e)
	}
	before := ordinaryNamespaceSnapshot(t, x.f)
	stateFD, operationFD := s.state.lock.Fd(), s.lock.Fd()
	for _, in := range fixture.inputs {
		if _, e := in.source.Seek(17, 0); e != nil {
			t.Fatal(e)
		}
	}
	if e = a.validateNativePrograms(ctx); e != nil {
		t.Fatal("signed structural native images refused under original Stop", e)
	}
	if !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, x.f)) || len(x.jobs) != 2 || s.state.lock.Fd() != stateFD || s.lock.Fd() != operationFD {
		t.Fatal("native inspection actuated or changed original state/leases")
	}
	for _, in := range fixture.inputs {
		if off, e := in.source.Seek(0, 1); e != nil || off != 17 {
			t.Fatal("borrowed original program description moved/closed", off, e)
		}
	}
	hits := 0
	x.f.hook = func(stage string) error {
		if stage == "runtime-program-images-before-final" {
			hits++
			fixture.policy.Epoch++ // Explicit TEST revocation, not production repair.
			return os.WriteFile(x.f.root.Name()+runtimeProgramAuthorityPath, programApprovalWire(t, fixture.policy), 0600)
		}
		return nil
	}
	if e = a.validateNativePrograms(ctx); e == nil || hits != 1 {
		t.Fatal("post-parser revocation survived the record/FD/source tail", e, hits)
	}
	x.f.hook = nil
	revoked := ordinaryNamespaceSnapshot(t, x.f)
	if a.validateNativePrograms(ctx) == nil || !reflect.DeepEqual(revoked, ordinaryNamespaceSnapshot(t, x.f)) {
		t.Fatal("refusal restored authority or reused a cached signature")
	}
	// Explicit TEST administrator issues a NEW current-epoch certificate. Never
	// roll the authority backwards or silently repair it to revive the old pin.
	fixture.cert.Claim.Epoch = fixture.policy.Epoch
	programApprovalSign(t, &fixture.cert, key, "Xandbox runtime program approval v1\x00")
	if e = os.WriteFile(x.f.root.Name()+fixture.certificate, programApprovalWire(t, fixture.cert), 0600); e != nil {
		t.Fatal(e)
	}
	renewed, e := s.approveRuntimePrograms(ctx, base, operation, p, fixture.inputs)
	if e != nil || renewed.validateNativePrograms(ctx) != nil || a.validateNativePrograms(ctx) == nil {
		t.Fatal("new explicit approval failed or old observation revived", e)
	}
	current := ordinaryNamespaceSnapshot(t, x.f)
	s.close()
	if renewed.validateNativePrograms(ctx) == nil || !reflect.DeepEqual(current, ordinaryNamespaceSnapshot(t, x.f)) || len(x.jobs) != 2 {
		t.Fatal("current valid authority bypassed original scope retirement")
	}
}
