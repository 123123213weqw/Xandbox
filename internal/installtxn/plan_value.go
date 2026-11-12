package installtxn

// Internal transaction values are already typed; raw transaction readers still
// prove bounded canonical JSON (with the original strict rejection path) before
// calling this.
// Recheck the SAME semantic policy and serialized ceiling without parsing our
// own JSON a second time. No raw bytes, cache, relaxed decoder or file proof is
// accepted here. Current Plan strings are closed ASCII paths/digests/device IDs;
// there are no float/map/slice/interface fields or custom JSON normalization.
func validatedPlanValue(original Plan) (Plan, error) {
	p := snapshotPlanValue(original)
	if len(encode(p)) > MaxPlan || validatePlan(p) != nil || !samePlanValue(original, p) {
		return p, ErrPolicy
	}
	return p, nil
}

// Policy is the ONLY reference-valued field of Plan. Keep a private value while
// validating, and recompare its value afterwards; pointer identity is not proof.
// The schema-contract/differential tests require review if this shape changes.
func snapshotPlanValue(p Plan) Plan {
	if p.Policy != nil {
		policy := *p.Policy
		p.Policy = &policy
	}
	return p
}

func samePlanValue(a, b Plan) bool {
	if a.Policy == nil || b.Policy == nil {
		if a.Policy != b.Policy {
			return false
		}
	} else if *a.Policy != *b.Policy {
		return false
	}
	a.Policy, b.Policy = nil, nil
	return a == b
}
