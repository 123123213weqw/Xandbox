package installtxn

import (
	"bytes"
	"strings"
	"testing"
)

func sampleUpdateInspection() UpdateInspectionPlan {
	return UpdateInspectionPlan{Version: 1, InstallCommitSHA256: strings.Repeat("a", 64), ReleaseRevision: 2, CandidateRelease: strings.Repeat("b", 64), RetainedRelease: strings.Repeat("c", 64)}
}

func TestUpdateInspectionPlanClosedAndBoundToBothReleases(t *testing.T) {
	p := sampleUpdateInspection()
	if _, e := DecodeUpdateInspection(encode(p)); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*UpdateInspectionPlan){
		"version":            func(p *UpdateInspectionPlan) { p.Version = 2 },
		"commit":             func(p *UpdateInspectionPlan) { p.InstallCommitSHA256 = "latest" },
		"revision":           func(p *UpdateInspectionPlan) { p.ReleaseRevision = 1 },
		"overflow":           func(p *UpdateInspectionPlan) { p.ReleaseRevision = ^uint64(0) },
		"candidate":          func(p *UpdateInspectionPlan) { p.CandidateRelease = strings.Repeat("B", 64) },
		"previous":           func(p *UpdateInspectionPlan) { p.RetainedRelease = "" },
		"same":               func(p *UpdateInspectionPlan) { p.CandidateRelease = p.RetainedRelease },
		"policy-unbound":     func(p *UpdateInspectionPlan) { p.PolicyRevision = 1 },
		"policy-no-revision": func(p *UpdateInspectionPlan) { p.PolicySHA256 = strings.Repeat("d", 64) },
		"policy-overflow":    func(p *UpdateInspectionPlan) { p.PolicyRevision = ^uint64(0); p.PolicySHA256 = strings.Repeat("d", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			p := sampleUpdateInspection()
			change(&p)
			if _, e := DecodeUpdateInspection(encode(p)); e == nil {
				t.Fatal("unbound inspection accepted")
			}
		})
	}
	for _, extra := range []string{`,"force":true}`, `,"version":1}`, `,"Version":1}`, `,"state_backup":"/private/old-ledger"}`, `,"unit":"other.service"}`} {
		raw := append(bytes.TrimSuffix(encode(p), []byte("}\n")), []byte(extra)...)
		if _, e := DecodeUpdateInspection(raw); e == nil {
			t.Fatal("unknown/duplicate authority accepted")
		}
	}
	for _, raw := range [][]byte{nil, []byte("null"), append(encode(p), []byte("{}")...), bytes.Repeat([]byte(" "), MaxPlan+1)} {
		if _, e := DecodeUpdateInspection(raw); e == nil {
			t.Fatal("nonclosed input accepted")
		}
	}
	p.PolicyRevision, p.PolicySHA256 = 2, strings.Repeat("d", 64)
	if _, e := DecodeUpdateInspection(encode(p)); e != nil {
		t.Fatal("exact current policy cannot be pinned", e)
	}
}
