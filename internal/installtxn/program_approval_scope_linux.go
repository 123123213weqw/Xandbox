//go:build linux

package installtxn

import "context"

// Nonserializable live program-byte approval. NOT a file-consumer capability,
// executable/ABI/state compatibility, activation, release or rollback right.
// The producer owns every original program FD; closing/rebinding/changing one
// invalidates recheck. Scope close invalidates the original operation/state FDs.
type runtimeProgramApproval struct {
	scope           *runtimeScope
	base, operation string
	proof           runtimeResultsStoppedWorkProof
	inputs          []runtimeProgramInput
	evidence        runtimeProgramEvidence
}

func (s *runtimeScope) programApprovalSource(ctx context.Context, base, operation string, p *runtimeResultsStoppedWorkProof) error {
	source, e := s.readResultsStateSource(ctx, base, operation, p)
	if e != nil {
		return e
	}
	if e = s.resultsStateLeaseHeld(ctx, p.state); e != nil {
		return e
	}
	return resultsStateOriginalsExited(source.stop)
}
func (s *runtimeScope) programApprovalPolicy(ctx context.Context, base, operation string, p *runtimeResultsStoppedWorkProof) error {
	if _, bounded := ctx.Deadline(); !bounded || s == nil || p == nil || p.scope != s || p.closed.scope != s || !digestPattern.MatchString(base) || !requestPattern.MatchString(operation) {
		return ErrPolicy
	}
	return nil
}
func (s *runtimeScope) approveRuntimePrograms(ctx context.Context, base, operation string, p *runtimeResultsStoppedWorkProof, inputs []runtimeProgramInput) (*runtimeProgramApproval, error) {
	if e := s.programApprovalPolicy(ctx, base, operation, p); e != nil {
		return nil, e
	}
	// Private immutable metadata copy, not a program-byte/authority cache. The
	// original descriptor objects remain borrowed, never duplicated/reacquired.
	out := &runtimeProgramApproval{scope: s, base: base, operation: operation, proof: *p, inputs: append([]runtimeProgramInput(nil), inputs...)}
	e := s.run(ctx, func(f *filesystem) error {
		if e := s.programApprovalSource(ctx, base, operation, &out.proof); e != nil {
			return e
		}
		var e error
		out.evidence, e = f.inspectRuntimeProgramApproval(ctx, out.inputs)
		if e != nil {
			return e
		}
		// No injectable manager/kernel callback after this source/FD/pidfd tail.
		return s.programApprovalSource(ctx, base, operation, &out.proof)
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
func (a *runtimeProgramApproval) recheck(ctx context.Context) error {
	if a == nil || a.scope == nil {
		return ErrPolicy
	}
	s := a.scope
	if e := s.programApprovalPolicy(ctx, a.base, a.operation, &a.proof); e != nil {
		return e
	}
	return s.run(ctx, func(f *filesystem) error {
		if e := s.programApprovalSource(ctx, a.base, a.operation, &a.proof); e != nil {
			return e
		}
		current, e := f.inspectRuntimeProgramApproval(ctx, a.inputs)
		if e != nil {
			return e
		}
		if current != a.evidence {
			return ErrConflict
		}
		return s.programApprovalSource(ctx, a.base, a.operation, &a.proof)
	})
}
