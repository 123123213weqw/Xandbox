//go:build linux

package installtxn

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeScopeProgramApprovalOriginalFDsRevocationAndRetirement(t *testing.T) {
	// ONE lifecycle history, not a shared cached fixture across cases/rounds.
	// Real owned V2 actor/close/Stop/original BSD FD; backend/kernel positives
	// remain explicit MODELS. Authenticated bytes below are DATA, not ELFs.
	x, s, p, _ := resultsStateModel(t, false)
	fixture := programDiskOn(t, x.f)
	ctx, cancel := workStopContext(t)
	defer cancel()
	base, operation := digest(encode(x.tx)), runtimeReq("b")
	before := ordinaryNamespaceSnapshot(t, x.f)
	stateFD, operationFD := s.state.lock.Fd(), s.lock.Fd()
	if a, e := s.approveRuntimePrograms(ctx, base, operation, nil, fixture.inputs); e == nil || a != nil {
		t.Fatal("signed bytes bypassed authentic Stop proof")
	}
	foreign := *p
	foreign.scope = &runtimeScope{}
	if a, e := s.approveRuntimePrograms(ctx, base, operation, &foreign, fixture.inputs); e == nil || a != nil {
		t.Fatal("foreign scope accepted")
	}
	wrong := *p
	wrong.stop = strings.Repeat("f", 64)
	if a, e := s.approveRuntimePrograms(ctx, base, operation, &wrong, fixture.inputs); e == nil || a != nil {
		t.Fatal("forged receipt accepted")
	}
	if e := (*runtimeProgramApproval)(nil).recheck(ctx); e == nil {
		t.Fatal("nil report accepted")
	}
	if e := (&runtimeProgramApproval{}).recheck(ctx); e == nil {
		t.Fatal("zero/serialized report accepted")
	}
	a, e := s.approveRuntimePrograms(ctx, base, operation, p, fixture.inputs)
	if e != nil || a == nil {
		t.Fatal("authentic source + original descriptors + actual signed bytes refused", e)
	}
	// Caller metadata is copied, but the SAME original descriptor objects and
	// state/OFD ownership remain mandatory. No bytes or authority are cached.
	fixture.inputs[0].file.SHA256 = strings.Repeat("0", 64)
	fixture.inputs[0].source = nil
	if e = a.recheck(ctx); e != nil {
		t.Fatal("private metadata snapshot aliased caller slice", e)
	}
	if s.state.lock.Fd() != stateFD || s.lock.Fd() != operationFD || len(x.jobs) != 2 || !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, x.f)) {
		t.Fatal("approval changed original leases/runtime state or actuated jobs")
	}
	if raw, e := json.Marshal(a); e != nil || string(raw) != "{}" {
		t.Fatal("live approval unexpectedly wire-serializable")
	}
	var replay runtimeProgramApproval
	if e = json.Unmarshal([]byte("{}"), &replay); e != nil || replay.recheck(ctx) == nil {
		t.Fatal("serialized report reconstructed a live approval")
	}
	// Revocation is an explicit TEST setup change. Failure must preserve it,
	// not silently restore an old authority or turn a cached signature into permission.
	fixture.policy.Epoch++
	if e = os.WriteFile(x.f.root.Name()+runtimeProgramAuthorityPath, programApprovalWire(t, fixture.policy), 0600); e != nil {
		t.Fatal(e)
	}
	revoked := ordinaryNamespaceSnapshot(t, x.f)
	if e = a.recheck(ctx); e == nil {
		t.Fatal("old approval survived live authority revocation")
	}
	if !reflect.DeepEqual(revoked, ordinaryNamespaceSnapshot(t, x.f)) || len(x.jobs) != 2 || s.state.lock.Fd() != stateFD {
		t.Fatal("rejection mutated state or original FD")
	}
	s.close()
	if e = a.recheck(ctx); e == nil {
		t.Fatal("approval survived retirement/reacquired original lease")
	}
}
