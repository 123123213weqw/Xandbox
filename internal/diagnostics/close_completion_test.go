package diagnostics

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type completionStore struct {
	entered, release chan struct{}
	once             sync.Once
	closed           atomic.Bool
	closeErr         error
}

func (s *completionStore) append(Event) error {
	if s.entered != nil {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	return nil
}
func (s *completionStore) close() error {
	s.closed.Store(true)
	return s.closeErr
}

// The writer finished BEFORE this canceled call. Reporting ErrPending here
// would claim resources remain owned even though both descriptors are closed.
func TestLoggerCloseCompletedWriterBeatsExpiredContext(t *testing.T) {
	for _, failClose := range []bool{false, true} {
		name := "clean"
		store := &completionStore{}
		var wantWriteErrors uint64
		if failClose {
			name = "write_error"
			store.closeErr = errors.New("fixed store-close failure")
			wantWriteErrors = 1
		}
		t.Run(name, func(t *testing.T) {
			logger := newLogger(store)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			want := error(nil)
			if failClose {
				want = ErrWrite
			}
			if got := logger.Close(ctx); got != want || !store.closed.Load() {
				t.Fatal("initial writer completion was not published", got)
			}
			select {
			case <-logger.done:
			default:
				t.Fatal("Close returned before writer completion")
			}
			expired, expire := context.WithCancel(context.Background())
			expire()
			for range 100 {
				if got := logger.Close(expired); got != want {
					t.Fatal("fully closed writer reported pending after caller cancellation", got)
				}
			}
			if stats := logger.Stats(); stats.Written != 1 || stats.WriteErrors != wantWriteErrors {
				t.Fatal("completion changed durable record/error accounting", stats)
			}
		})
	}
}

// Real unfinished storage still owns its worker. No deadline is enlarged and
// no caller may report a successful close, revoke the store or admit new work.
func TestLoggerCloseCanceledPendingStillRetainsWriter(t *testing.T) {
	store := &completionStore{entered: make(chan struct{}), release: make(chan struct{})}
	logger := newLogger(store)
	var release sync.Once
	unblock := func() { release.Do(func() { close(store.release) }) }
	t.Cleanup(func() { unblock(); _ = logger.Close(context.Background()) })
	if !logger.Emit(ServiceMock, Other) {
		t.Fatal("initial enqueue refused")
	}
	select {
	case <-store.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("owned writer did not enter fixed append")
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	for range 100 {
		if err := logger.Close(expired); !errors.Is(err, ErrPending) {
			t.Fatal("unfinished writer was acknowledged", err)
		}
	}
	if store.closed.Load() || logger.Emit(ServiceMock, Other) {
		t.Fatal("pending Close revoked storage or admitted new work")
	}
	select {
	case <-logger.done:
		t.Fatal("writer completion was invented before release")
	default:
	}
	unblock()
	ctx, finish := context.WithTimeout(context.Background(), 2*time.Second)
	defer finish()
	if err := logger.Close(ctx); err != nil || !store.closed.Load() {
		t.Fatal("original writer did not complete after release", err)
	}
	for range 100 {
		if err := logger.Close(expired); err != nil {
			t.Fatal("completed original writer became pending again", err)
		}
	}
}
