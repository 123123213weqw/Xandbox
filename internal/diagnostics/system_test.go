package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

type panicMethods []byte

func (panicMethods) Error() string        { panic("Error callback") }
func (panicMethods) Is(error) bool        { panic("Is callback") }
func (panicMethods) As(any) bool          { panic("As callback") }
func (panicMethods) Unwrap() error        { panic("Unwrap callback") }
func (panicMethods) LogValue() slog.Value { panic("LogValue callback") }
func TestSystemReasonHasNoCallerCallbacksAndBoundedConcreteChains(t *testing.T) {
	for _, tc := range []struct {
		e error
		r Reason
	}{{nil, Other}, {syscall.EIO, IOFailure}, {syscall.EDQUOT, QuotaExceeded}, {syscall.ENOSPC, NoSpace}, {syscall.EROFS, ReadOnly}, {context.Canceled, Cancelled}, {context.DeadlineExceeded, Deadline}, {panicMethods{1}, Other}, {fmt.Errorf("trusted unknown wrapper: %w", syscall.EIO), Other}, {&os.PathError{Op: "secret-op", Path: "secret-path", Err: syscall.EDQUOT}, QuotaExceeded}, {&os.SyscallError{Syscall: "secret-op", Err: syscall.EIO}, IOFailure}, {&os.LinkError{Op: "secret", Old: "secret", New: "secret", Err: syscall.EROFS}, ReadOnly}, {&Fault{Reason: DiagnosticsUnavailable, Cause: &os.PathError{Err: syscall.ENOSPC}}, NoSpace}} {
		if got := SystemReason(tc.e); got != tc.r {
			t.Fatal("closed class mismatch", got, tc.r)
		}
	}
	cyclic := &os.PathError{}
	cyclic.Err = cyclic
	if SystemReason(cyclic) != Other {
		t.Fatal("cyclic path wrapper")
	}
	f := &Fault{Reason: Other}
	f.Cause = f
	if SystemReason(f) != Other {
		t.Fatal("cyclic own wrapper")
	}
	if SystemReason((*os.PathError)(nil)) != Other || SystemReason((*Fault)(nil)) != Other {
		t.Fatal("nil concrete error")
	}
	// Original version1 ordinals remain stable when extending the closed enum.
	if Other != 0 || Deadline != 1 || Cancelled != 2 || Configuration != 3 || StateLock != 4 || AuthMode != 5 || DiagnosticsUnavailable != 6 || IOFailure != 7 {
		t.Fatal("persisted enum was renumbered")
	}
}

func TestProducerCountersAreConcurrentIndependentAndExcludeInvalidEnums(t *testing.T) {
	l := &Logger{closing: true}
	var wg sync.WaitGroup
	for _, r := range []Reason{IOFailure, QuotaExceeded, ReadOnly} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				l.Emit(PrepareFailed, r)
			}
		}()
	}
	wg.Wait()
	l.Emit(Unknown, IOFailure)
	l.Emit(PrepareFailed, reasonCount)
	l.Emit(kindCount, QuotaExceeded)
	s := l.Stats()
	if s.PrepareIO != 1000 || s.PrepareQuota != 1000 || s.PrepareOther != 1000 || s.Dropped != 3003 || s.Written != 0 || s.Enqueued != 0 {
		t.Fatal(s)
	}
}

func TestPrimitiveHandlerHasNoHeapAllocationOrCallbacks(t *testing.T) {
	l := &Logger{closing: true}
	h := &Handler{Logger: l}
	r := slog.NewRecord(timeForTest(), slog.LevelError, "Firecracker preparation failed", 0)
	r.AddAttrs(slog.Int(ReasonAttribute, int(IOFailure)), slog.Any("discarded", panicMethods{}))
	if n := testing.AllocsPerRun(1000, func() { h.Handle(context.Background(), r) }); n != 0 {
		t.Fatal("closed handler allocated", n)
	}
}
func TestHandlerOnlyAcceptsOneDirectBoundedPrimitiveReason(t *testing.T) {
	s := &testStore{}
	l := newLogger(s)
	h := &Handler{Logger: l}
	record := func(msg string, attrs ...slog.Attr) {
		r := slog.NewRecord(timeForTest(), slog.LevelError, msg, 0)
		r.AddAttrs(attrs...)
		if e := h.Handle(context.Background(), r); e != nil {
			t.Fatal(e)
		}
	}
	record("Firecracker preparation failed", slog.Int(ReasonAttribute, int(IOFailure)), slog.Any("error", panicMethods{1}))
	record("Firecracker preparation failed", slog.Any(ReasonAttribute, panicMethods{1}))
	record("Firecracker preparation failed", slog.Int(ReasonAttribute, int(QuotaExceeded)), slog.Int(ReasonAttribute, int(IOFailure)))
	record("Firecracker preparation failed", slog.Int(ReasonAttribute, int(reasonCount)))
	record("Firecracker preparation failed", slog.Int(ReasonAttribute, -1))
	record("Firecracker preparation failed", slog.Group("secret", slog.Int(ReasonAttribute, int(IOFailure))))
	record("unknown secret message", slog.Int(ReasonAttribute, int(IOFailure)), slog.Any("error", panicMethods{1}))
	record("Firecracker preparation failed", slog.Int(ReasonAttribute, int(IOFailure)), slog.Any("a", panicMethods{}), slog.Any("b", panicMethods{}), slog.Any("c", panicMethods{}), slog.Any("d", panicMethods{}))
	closeTest(t, l)
	events := s.snapshot()
	if len(events) != 9 || events[0].Reason != IOFailure {
		t.Fatal("primitive class not retained")
	}
	for _, e := range events[1:] {
		if e.Reason != Other {
			t.Fatal("arbitrary/duplicate/nested/oversize reason accepted")
		}
	}
	st := l.Stats()
	if st.PrepareIO != 1 || st.PrepareQuota != 0 || st.PrepareOther != 6 {
		t.Fatal(st)
	}
}
func timeForTest() time.Time { return time.Unix(1, 0) }
func TestProducerCauseCountersSurviveQueueAndWriterLoss(t *testing.T) {
	s := &testStore{entered: make(chan struct{}), release: make(chan struct{}), appendErr: errors.New("private storage error")}
	l := newLogger(s)
	l.Emit(PrepareFailed, IOFailure)
	<-s.entered
	for range QueueCapacity {
		l.Emit(PrepareFailed, QuotaExceeded)
	}
	for range 1000 {
		l.Emit(PrepareFailed, IOFailure)
	}
	st := l.Stats()
	if st.PrepareIO != 1001 || st.PrepareQuota != 64 || st.Dropped != 1000 || st.Written != 0 || st.Queued != 64 {
		t.Fatal(st)
	}
	close(s.release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := l.Close(ctx); !errors.Is(e, ErrWrite) {
		t.Fatal(e)
	}
	if l.Emit(PrepareFailed, ReadOnly) {
		t.Fatal("dead writer accepted event")
	}
	st = l.Stats()
	if st.PrepareIO != 1001 || st.PrepareQuota != 64 || st.PrepareOther != 1 || st.Written != 0 || st.WriteErrors != 1 || st.Queued != 0 || st.Dropped != 1066 {
		t.Fatal(st)
	}
}
