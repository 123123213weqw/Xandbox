package telemetry

import (
	"context"
	"math"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCreationTraceClosedBoundedHeaderAndFreshRequest(t *testing.T) {
	ctx := WithCreationTrace(context.Background())
	for phase := CreationPhase(0); phase < creationPhaseCount; phase++ {
		span := StartCreation(ctx, phase)
		span.start = time.Now().Add(-2 * time.Millisecond)
		span.End()
		span.End()
	}
	header := CreationServerTiming(ctx)
	parts := strings.Split(header, ", ")
	if len(parts) != int(creationPhaseCount) || len(header) >= 2048 {
		t.Fatal("header is not fixed-size closed data", header)
	}
	for phase, part := range parts {
		if !regexp.MustCompile(`^` + creationNames[phase] + `;dur=[0-9]+\.[0-9]{3};desc="n1"$`).MatchString(part) {
			t.Fatal("noncanonical or duplicate observation", part)
		}
	}
	if CreationServerTiming(WithCreationTrace(ctx)) != "" {
		t.Fatal("new request inherited prior observations")
	}
}

func TestCreationTraceCarriesOnlyObserverNotCallerLifetimeOrValues(t *testing.T) {
	type key struct{}
	source, cancelSource := context.WithDeadline(context.WithValue(context.Background(), key{}, "caller-secret"), time.Now().Add(time.Hour))
	source = WithCreationTrace(source)
	destination, cancelDestination := context.WithTimeout(context.WithValue(context.Background(), key{}, "lifecycle-value"), 2*time.Hour)
	defer cancelDestination()
	carried := CarryCreationTrace(destination, source)
	want, _ := destination.Deadline()
	got, ok := carried.Deadline()
	if !ok || got != want || carried.Value(key{}) != "lifecycle-value" {
		t.Fatal("observer replaced lifecycle context policy")
	}
	cancelSource()
	if carried.Err() != nil {
		t.Fatal("observer transfer added caller cancellation")
	}
	StartCreation(carried, DriverPrepareSlot).End()
	if !strings.Contains(CreationServerTiming(source), "xa_driver_slot;") {
		t.Fatal("observer was lost across lifecycle context")
	}
	cancelDestination()
	if carried.Err() != context.Canceled {
		t.Fatal("observer suppressed original lifecycle cancellation")
	}
	if CarryCreationTrace(destination, context.Background()) != destination {
		t.Fatal("unobserved path must retain original context")
	}
}

func TestCreationTraceConcurrentEndAndSnapshot(t *testing.T) {
	ctx := WithCreationTrace(context.Background())
	span := StartCreation(ctx, CoreAdmission)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); span.End(); _ = CreationServerTiming(ctx) }()
	}
	wg.Wait()
	if !strings.HasSuffix(CreationServerTiming(ctx), `;desc="n1"`) {
		t.Fatal("duplicate completion was counted", CreationServerTiming(ctx))
	}
	wg = sync.WaitGroup{}
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); StartCreation(ctx, CoreDriver).End() }()
	}
	wg.Wait()
	if !strings.HasSuffix(CreationServerTiming(ctx), `;desc="n32"`) {
		t.Fatal("independent calls were not aggregated", CreationServerTiming(ctx))
	}
}

func TestCreationTraceDisabledInvalidAndSaturating(t *testing.T) {
	ctx := context.Background()
	if n := testing.AllocsPerRun(100, func() { StartCreation(ctx, CoreDriver).End() }); n != 0 {
		t.Fatal("disabled observer allocated", n)
	}
	var zero CreationSpan
	zero.End()
	if CreationServerTiming(ctx) != "" {
		t.Fatal("unobserved is not absent")
	}
	ctx = WithCreationTrace(ctx)
	StartCreation(ctx, CreationPhase(255)).End()
	span := StartCreation(ctx, CoreDriver)
	span.start = time.Now().Add(time.Hour)
	span.End()
	if CreationServerTiming(ctx) != "" {
		t.Fatal("invalid/negative measurement became zero latency")
	}
	trace := ctx.Value(creationKey{}).(*creationTrace)
	trace.values[CoreDriver] = creationObservation{calls: math.MaxUint64, total: time.Duration(math.MaxInt64)}
	StartCreation(ctx, CoreDriver).End()
	if trace.values[CoreDriver].calls != math.MaxUint64 || trace.values[CoreDriver].total != time.Duration(math.MaxInt64) {
		t.Fatal("timing/count wrapped")
	}
	if strings.ContainsAny(CreationServerTiming(ctx), "\r\n") || len(CreationServerTiming(ctx)) >= 2048 {
		t.Fatal("unbounded or injected header")
	}
}
