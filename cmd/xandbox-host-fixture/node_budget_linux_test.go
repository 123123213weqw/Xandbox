//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestNodeBudgetFixtureIsExplicitCPU8AndCannotOperateOnL0(t *testing.T) {
	p := testPolicy()
	p.Profile = "node-budget-v1"
	m, d, c, e := p.resources()
	if e != nil || p.validate() != nil || m != 8192 || d != 12<<30 || c != 10<<30 || p.cpuCount() != 8 || p.pidCount() != 256 {
		t.Fatal("explicit node resource bounds")
	}
	args := p.arguments()
	smp := ""
	for i, a := range args {
		if a == "-smp" {
			smp = args[i+1]
		}
	}
	if smp != "8" {
		t.Fatal("new CPU bound not passed to actual QEMU")
	}
	p.Profile = "quota-copy-v1"
	if p.cpuCount() != 4 || p.pidCount() != 128 {
		t.Fatal("silently enlarged old profile")
	}
	p.Profile = "node-budget-v2"
	if p.validate() == nil || p.arguments() != nil {
		t.Fatal("unknown resource profile")
	}
	ctx := context.Background()
	n := &node{nodeBudget: true, quotaDriver: true}
	if n.initializeNodeBudget() == nil || runNodeBudgetDaemon(false) == nil || runNodeBudgetDaemon(true) == nil {
		t.Fatal("node setup/child escaped L1")
	}
	if _, e = n.nodeBudgetCheckpoint(ctx); e == nil {
		t.Fatal("budget checkpoint escaped L1")
	}
	if _, e = n.nodeBudgetRecover(ctx); e == nil {
		t.Fatal("budget recovery escaped L1")
	}
	if n.budgetNegative(ctx, false) == nil || budgetVM(sandbox.Ref{}) == nil || budgetAbsent(sandbox.Ref{}) == nil {
		t.Fatal("budget helper escaped L1")
	}
	if _, _, e = budgetOwner(sandbox.Ref{}); e == nil {
		t.Fatal("budget owner reader escaped L1")
	}
	for _, op := range []string{"node-budget-checkpoint", "node-budget-recover"} {
		if (nodeRequest{Version: 1, Operation: op}).validate() != nil || (nodeRequest{Version: 1, Operation: op, Phase: "arbitrary"}).validate() == nil {
			t.Fatal("node operation must be phase-less fixed profile")
		}
	}
}
