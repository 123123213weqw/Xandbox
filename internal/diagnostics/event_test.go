package diagnostics

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testStore struct {
	mu                  sync.Mutex
	events              []Event
	entered, release    chan struct{}
	once                sync.Once
	appendErr, closeErr error
	closed              atomic.Bool
}

func (s *testStore) append(e Event) error {
	if s.entered != nil {
		s.once.Do(func() { close(s.entered); <-s.release })
	}
	if s.appendErr != nil {
		return s.appendErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}
func (s *testStore) close() error { s.closed.Store(true); return s.closeErr }
func closeTest(t *testing.T, l *Logger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e := l.Close(ctx); e != nil {
		t.Fatal(e)
	}
}
func (s *testStore) snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

type neverFormat struct{}

func (neverFormat) Error() string        { panic("arbitrary error must not be formatted") }
func (neverFormat) LogValue() slog.Value { panic("arbitrary slog value must not be resolved") }

func TestHandlerNeverFormatsOrRetainsInput(t *testing.T) {
	s := &testStore{}
	l := newLogger(s)
	h := &Handler{Logger: l}
	logger := slog.New(h).With("password", neverFormat{}).WithGroup("secret-group")
	logger.Error("Firecracker preparation failed", "error", neverFormat{}, "token", "secret-token")
	logger.Warn("secret-unknown-message", "attr", neverFormat{})
	closeTest(t, l)
	got := s.snapshot()
	if len(got) != 3 || got[0].Kind != PrepareFailed || got[1].Kind != Unknown || got[2].Kind != CollectorClosed {
		t.Fatal(got)
	}
	for _, e := range got {
		if !e.valid() || e.Reason != Other {
			t.Fatal(e)
		}
	}
	if !errors.Is(&Fault{Reason: Configuration, Cause: context.DeadlineExceeded}, context.DeadlineExceeded) {
		t.Fatal("unwrap lost")
	}
	if v := (&Fault{Reason: Configuration, Cause: neverFormat{}}).Error(); v != "diagnostic class: configuration" {
		t.Fatal(v)
	}
	if FailureReason(errors.Join(neverFormat{}, &Fault{Reason: AuthMode, Cause: neverFormat{}})) != AuthMode {
		t.Fatal("closed class lost")
	}
	if ReasonFor(neverFormat{}) != Other || ReasonFor(context.DeadlineExceeded) != Deadline || ReasonFor(context.Canceled) != Cancelled {
		t.Fatal("reason classification")
	}
}
func TestBoundedQueueAndCloseDoNotCloseBlockedStore(t *testing.T) {
	s := &testStore{entered: make(chan struct{}), release: make(chan struct{})}
	l := newLogger(s)
	if !l.Emit(PrepareFailed, Other) {
		t.Fatal("first")
	}
	<-s.entered
	for range QueueCapacity {
		if !l.Emit(PrepareFailed, Other) {
			t.Fatal("queue too small")
		}
	}
	for range 10000 {
		if l.Emit(PrepareFailed, Other) {
			t.Fatal("unbounded queue")
		}
	}
	st := l.Stats()
	if st.Enqueued != QueueCapacity+1 || st.Dropped != 10000 || st.Queued != QueueCapacity || st.Written != 0 || st.Capacity != QueueCapacity {
		t.Fatal(st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if e := l.Close(ctx); !errors.Is(e, ErrPending) {
		t.Fatal(e)
	}
	if s.closed.Load() {
		t.Fatal("closed underneath a blocked writer")
	}
	if l.Emit(ProcessStopped, Other) {
		t.Fatal("closing accepted new event")
	}
	close(s.release)
	closeTest(t, l)
	st = l.Stats()
	if !s.closed.Load() || st.Queued != 0 || st.Written != QueueCapacity+2 || st.WriteErrors != 0 || st.Dropped != 10001 {
		t.Fatal(st)
	}
	got := s.snapshot()
	if got[len(got)-1].Kind != CollectorClosed || got[len(got)-1].DroppedBefore != 10001 {
		t.Fatal("missing loss watermark")
	}
}
func TestFailedWriterRejectsAndAccountsPendingEvents(t *testing.T) {
	s := &testStore{entered: make(chan struct{}), release: make(chan struct{}), appendErr: neverFormat{}, closeErr: neverFormat{}}
	l := newLogger(s)
	l.Emit(PrepareFailed, Other)
	<-s.entered
	for range QueueCapacity {
		l.Emit(PrepareFailed, Other)
	}
	close(s.release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := l.Close(ctx); !errors.Is(e, ErrWrite) {
		t.Fatal(e)
	}
	if l.Emit(ProcessStopped, Other) {
		t.Fatal("dead writer accepted")
	}
	st := l.Stats()
	if st.Enqueued != QueueCapacity+1 || st.Dropped != QueueCapacity+2 || st.Queued != 0 || st.Written != 0 || st.WriteErrors != 2 || !s.closed.Load() {
		t.Fatal(st)
	}
}
func TestConcurrentEmitCloseAndStats(t *testing.T) {
	s := &testStore{}
	l := newLogger(s)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2000 {
				l.Emit(PrepareFailed, Other)
				_ = l.Stats()
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); closeTest(t, l) }()
	wg.Wait()
	closeTest(t, l)
	st := l.Stats()
	if st.Queued != 0 || st.Written < 1 || st.WriteErrors != 0 || st.Enqueued+st.Dropped != 24000 || st.Written != st.Enqueued+1 {
		t.Fatal(st)
	}
	got := s.snapshot()
	for i := 1; i < len(got); i++ {
		if got[i].DroppedBefore < got[i-1].DroppedBefore {
			t.Fatal("loss watermark regressed")
		}
	}
}
func TestNilAndClosedEnums(t *testing.T) {
	var l *Logger
	if l.Emit(Unknown, Other) || l.Close(context.Background()) != nil || l.Stats().Capacity != QueueCapacity {
		t.Fatal("nil logger")
	}
	s := &testStore{}
	l = newLogger(s)
	if l.Emit(kindCount, Other) || l.Emit(Unknown, reasonCount) {
		t.Fatal("invalid enum")
	}
	closeTest(t, l)
	if l.Stats().Dropped != 2 {
		t.Fatal(l.Stats())
	}
	if kindCount.String() != "unknown" || reasonCount.String() != "other" {
		t.Fatal("unclosed labels")
	}
}
