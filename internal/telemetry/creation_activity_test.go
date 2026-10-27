package telemetry

import (
	"context"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCreationActivityFixedVocabularyAndThirteenTimingSlots(t *testing.T) {
	if creationKindCount != 3 || creationPhaseCount != 13 || creationActivityPhaseCount != 15 || len(creationActivityNames) != 15 {
		t.Fatal("unreviewed observation vocabulary")
	}
	for phase, name := range creationNames {
		if name != creationActivityNames[phase] {
			t.Fatal("response timing vocabulary drifted")
		}
	}
	r := &Registry{}
	ctx := WithCreationTraceKind(context.Background(), r, CreationSessionSwitch)
	for phase := CreationPhase(0); phase < creationPhaseCount; phase++ {
		s := StartCreation(ctx, phase)
		if r.creation.phases[CreationSessionSwitch][phase].Load() != 1 {
			t.Fatal("actual entered phase absent")
		}
		s.End()
		s.End()
	}
	for _, phase := range []CreationActivityPhase{CreationPermitWait, CreationNodeCheck} {
		s := StartCreationActivity(ctx, phase)
		if r.creation.phases[CreationSessionSwitch][phase].Load() != 1 {
			t.Fatal("substage absent")
		}
		s.End()
	}
	if len(strings.Split(CreationServerTiming(ctx), ", ")) != 13 || strings.Contains(CreationServerTiming(ctx), "permit_wait") || strings.Contains(CreationServerTiming(ctx), "node_check") {
		t.Fatal("activity changed original thirteen timing entries")
	}
	EndCreationTrace(ctx)
	EndCreationTrace(ctx)
	text := string(r.Render(Gauges{}))
	count := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "xandbox_creation_") {
			count++
		}
	}
	if count != 50 || len(text) > 65536 || !strings.Contains(text, "xandbox_creation_activity_enabled 1\n") || !strings.Contains(text, "xandbox_creation_activity_invalid 0\n") {
		t.Fatal("unbounded or unavailable fixed exposition", count, len(text))
	}
	for kind := range creationKindCount {
		if r.creation.requests[kind].Load() != 0 {
			t.Fatal("handler scope leaked")
		}
		for phase := range creationActivityPhaseCount {
			if r.creation.phases[kind][phase].Load() != 0 {
				t.Fatal("phase leaked")
			}
		}
	}
}

func TestCreationActivityCancellationAndHandlerEndDoNotInventWorkReturn(t *testing.T) {
	r := &Registry{}
	parent, cancel := context.WithCancel(context.Background())
	ctx := WithCreationTraceKind(parent, r, CreationRaw)
	s := StartCreation(ctx, CoreDriver)
	cancel()
	if ctx.Err() != context.Canceled || r.creation.requests[CreationRaw].Load() != 1 || r.creation.phases[CreationRaw][CoreDriver].Load() != 1 {
		t.Fatal("caller cancellation falsely ended actual work")
	}
	EndCreationTrace(ctx)
	if r.creation.requests[CreationRaw].Load() != 0 || r.creation.phases[CreationRaw][CoreDriver].Load() != 1 {
		t.Fatal("handler completion falsely ended a carried lifecycle span")
	}
	s.End()
	if r.creation.phases[CreationRaw][CoreDriver].Load() != 0 {
		t.Fatal("real return not observed")
	}
}

func TestCreationActivityCarryKeepsRegistryNotCallerLifetimeOrPayload(t *testing.T) {
	type key struct{}
	r := &Registry{}
	source, stopSource := context.WithCancel(context.WithValue(context.Background(), key{}, "private-input"))
	source = WithCreationTraceKind(source, r, CreationSessionOpen)
	destination, stopDestination := context.WithTimeout(context.WithValue(context.Background(), key{}, "lifecycle-value"), time.Minute)
	defer stopDestination()
	carried := CarryCreationTrace(destination, source)
	want, _ := destination.Deadline()
	got, _ := carried.Deadline()
	stopSource()
	if got != want || carried.Err() != nil || carried.Value(key{}) != "lifecycle-value" {
		t.Fatal("observer transferred caller lifetime or values")
	}
	s := StartCreationActivity(carried, CreationPermitWait)
	if r.creation.phases[CreationSessionOpen][CreationPermitWait].Load() != 1 {
		t.Fatal("observer lost during original lifetime transfer")
	}
	s.End()
	EndCreationTrace(source)
	if strings.Contains(string(r.Render(Gauges{})), "private-input") {
		t.Fatal("request payload entered fixed observations")
	}
}

func TestCreationActivityDisabledInvalidAndAllocationFreePath(t *testing.T) {
	ctx := context.Background()
	if n := testing.AllocsPerRun(100, func() { StartCreationActivity(ctx, CreationPermitWait).End() }); n != 0 {
		t.Fatal("disabled path allocated", n)
	}
	legacy := WithCreationTrace(ctx)
	if StartCreationActivity(legacy, CreationPermitWait) != nil {
		t.Fatal("legacy trace enabled unrelated activity")
	}
	var disabled *Registry
	c := WithCreationTraceKind(ctx, disabled, CreationRaw)
	StartCreation(c, CoreDriver).End()
	EndCreationTrace(c)
	if !strings.Contains(string(disabled.Render(Gauges{})), "xandbox_creation_activity_enabled 0\n") {
		t.Fatal("disabled observation masquerades as enabled zero")
	}
	r := &Registry{}
	c = WithCreationTraceKind(ctx, r, creationKindCount)
	StartCreation(c, CoreDriver).End()
	EndCreationTrace(c)
	if !r.creation.invalid.Load() || r.creation.enabled.Load() {
		t.Fatal("invalid kind accepted or silently became known zero")
	}
	r = &Registry{}
	c = WithCreationTraceKind(ctx, r, CreationRaw)
	if StartCreationActivity(c, creationActivityPhaseCount) != nil || !r.creation.invalid.Load() {
		t.Fatal("invalid stage accepted or silently discarded")
	}
	EndCreationTrace(c)
}

func TestCreationActivityCountersRefuseWrapAndUnbalancedEnd(t *testing.T) {
	r := &Registry{}
	r.creation.requests[CreationRaw].Store(math.MaxInt64)
	ctx := WithCreationTraceKind(context.Background(), r, CreationRaw)
	if r.creation.requests[CreationRaw].Load() != math.MaxInt64 || !r.creation.invalid.Load() || r.creation.enabled.Load() {
		t.Fatal("overflow wrapped or invented valid observation")
	}
	EndCreationTrace(ctx)
	r = &Registry{}
	r.endCreationCounter(&r.creation.requests[CreationRaw])
	if r.creation.requests[CreationRaw].Load() != 0 || !r.creation.invalid.Load() {
		t.Fatal("unbalanced end wrapped or hid invalidity")
	}
	ctx = WithCreationTraceKind(context.Background(), r, CreationRaw)
	StartCreation(ctx, CoreDriver).End()
	EndCreationTrace(ctx)
	if !r.creation.invalid.Load() {
		t.Fatal("later valid work cleared sticky invalidity")
	}
}

func TestCreationActivityConcurrentEndsAndScrapesRemainBounded(t *testing.T) {
	r := &Registry{}
	ctx := WithCreationTraceKind(context.Background(), r, CreationSessionSwitch)
	s := StartCreation(ctx, CoreDriver)
	a := StartCreationActivity(ctx, CreationPermitWait)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				s.End()
				a.End()
				EndCreationTrace(ctx)
				c := WithCreationTraceKind(context.Background(), r, CreationRaw)
				StartCreation(c, CoreAdmission).End()
				EndCreationTrace(c)
				if len(r.Render(Gauges{})) > 65536 {
					t.Error("exposition grew with request history")
				}
			}
		}()
	}
	wg.Wait()
	if r.creation.invalid.Load() {
		t.Fatal("balanced concurrent scopes marked invalid")
	}
	for kind := range creationKindCount {
		if r.creation.requests[kind].Load() != 0 {
			t.Fatal("handler count leaked")
		}
		for phase := range creationActivityPhaseCount {
			if r.creation.phases[kind][phase].Load() != 0 {
				t.Fatal("phase count leaked")
			}
		}
	}
}
