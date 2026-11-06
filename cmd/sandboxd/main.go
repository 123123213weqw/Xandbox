package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/httpapi"
	"github.com/123123213weqw/Xandbox/internal/nodecontrol"
	"github.com/123123213weqw/Xandbox/internal/observability"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/session"
	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

// Keep the exclusive state lock reachable until process exit if a worker is
// still in uninterruptible cleanup I/O. Releasing it on run's return would let a
// second controller race that still-live worker against the same ledger.
var retainedStateLock func()

func releaseStateLock(unlock func(), unfinished bool) {
	if unfinished {
		retainedStateLock = unlock
		return
	}
	unlock()
}

func main() {
	if err := run(); err != nil {
		// Only a closed bootstrap class may reach stderr. Once the diagnostic
		// writer starts, even its failure must not fall back to a possibly blocked
		// inherited pipe after lifecycle/control shutdown.
		var bootstrap *bootstrapFailure
		if errors.As(err, &bootstrap) {
			fmt.Fprintln(os.Stderr, bootstrapMessage(bootstrap.reason))
		}
		os.Exit(processExitCode(err))
	}
}

// bootstrapFailure is deliberately not the underlying error's string.
type bootstrapFailure struct {
	reason diagnostics.Reason
	cause  error
}

func (e *bootstrapFailure) Error() string { return bootstrapMessage(e.reason) }
func (e *bootstrapFailure) Unwrap() error { return e.cause }
func bootstrapMessage(r diagnostics.Reason) string {
	switch r {
	case diagnostics.StateLock:
		return "sandboxd: state directory already locked"
	case diagnostics.AuthMode:
		return "sandboxd: choose exactly one authentication mode"
	case diagnostics.DiagnosticsUnavailable:
		return "sandboxd: private diagnostics unavailable"
	case diagnostics.NodeAdmission:
		return "sandboxd: frontend admission differs from immutable node policy"
	case diagnostics.NodePlacement:
		return "sandboxd: controller/publisher must be inside node control subtree"
	case diagnostics.IOBackingQueue:
		return "sandboxd: IO policy must name the exact runtime backing queue"
	case diagnostics.IODelegation:
		return "sandboxd: configured IO policy requires delegated io controller"
	case diagnostics.BackendBinding:
		return "sandboxd: backend binding changed; explicit offline migration is required"
	case diagnostics.IOFailure:
		return "sandboxd: input/output error"
	case diagnostics.QuotaExceeded:
		return "sandboxd: disk quota exceeded"
	case diagnostics.NoSpace:
		return "sandboxd: no space left on device"
	case diagnostics.ReadOnly:
		return "sandboxd: read-only file system"
	case diagnostics.QuotaCapabilities:
		return "sandboxd: quota requires CAP_SYS_RESOURCE absent from all capability sets"
	case diagnostics.QuotaFilesystem:
		return "sandboxd: quota runtime filesystem UUID changed"
	case diagnostics.QuotaOwnership:
		return "sandboxd: unowned nonempty quota record requires operator reconciliation"
	case diagnostics.QuotaMount:
		return "sandboxd: quota requires the exact writable ext4 mount with enforced prjquota"
	default:
		return "sandboxd: configuration or bootstrap failure"
	}
}

func run() error { return runArgs(os.Args[1:]) }
func runArgs(args []string) (retErr error) {
	// Sanitize existing library slog producers from the start, including errors
	// during bootstrap/recovery. Never restore an unsanitized handler while a
	// retained worker may still be alive after run returns.
	slog.SetDefault(slog.New(&diagnostics.Handler{}))
	started := false
	defer func() {
		if retErr != nil && !started {
			reason := firecracker.DiagnosticReason(retErr)
			if reason == diagnostics.Other {
				reason = diagnostics.FailureReason(retErr)
			}
			if reason == diagnostics.Other {
				reason = diagnostics.Configuration
			}
			retErr = &bootstrapFailure{reason: reason, cause: retErr}
		}
	}()
	flags := flag.NewFlagSet("sandboxd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	stateDir := flags.String("state-dir", "", "required private state directory")
	backend := flags.String("backend", "", "required: mock or firecracker (experimental Linux/KVM)")
	firecrackerConfig := flags.String("firecracker-config", "", "private pinned-asset Firecracker configuration")
	maxInstances := flags.Int("max-instances", 32, "maximum allocated, including unreclaimed instances")
	maxRecords := flags.Int("max-records", 10_000, "maximum retained records, including tombstones; lowering does not block recovery")
	maxTenantRecords := flags.Int("max-tenant-records", 0, "retained records per tenant; 0 = min(1000, max-records)")
	migrateLedger := flags.Bool("migrate-ledger", false, "offline: validate and upgrade existing legacy ledger, then exit; no driver or API")
	authFile := flags.String("auth-file", "", "private digest-only authentication configuration")
	stopWorkers := flags.Int("stop-workers", 0, "background stop workers; 0 = min(4, instance capacity)")
	cleanupWorkers := flags.Int("cleanup-workers", 0, "cleanup workers; 0 = min(2, instance capacity)")
	workQueueSize := flags.Int("work-queue-size", 0, "queue slots PER pool; 0 = min(32, instance capacity)")
	insecureMock := flags.Bool("insecure-mock", false, "explicitly allow unauthenticated local mock simulation")
	maxSessions := flags.Int("max-sessions", 1000, "maximum retained session records, including closed tombstones")
	maxTenantSessions := flags.Int("max-tenant-sessions", 0, "retained sessions per tenant; 0 = min(100,max-sessions)")
	sessionHistory := flags.Int("session-history", 64, "maximum retained attempts per session, including initial create; 1..64")
	metricsEnabled := flags.Bool("metrics", false, "operator-only metrics on private state-dir/metrics.sock; never on tenant API or TCP")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stdout, "usage: sandboxd -backend mock|firecracker -state-dir DIR [-auth-file PATH|-insecure-mock]; mock provides NO isolation")
			return nil
		}
		return &diagnostics.Fault{Reason: diagnostics.Configuration, Cause: err}
	}
	if *stateDir == "" || (!*migrateLedger && *backend != "mock" && *backend != "firecracker") || *maxInstances < 1 || *maxInstances > 10_000 || *maxRecords < 1 || *maxRecords > sandbox.MaxLedgerRecords || *maxTenantRecords < 0 || *maxTenantRecords > *maxRecords || *maxSessions < 1 || *maxSessions > session.MaxRecords || *maxTenantSessions < 0 || *maxTenantSessions > *maxSessions || *sessionHistory < 1 || *sessionHistory > session.MaxHistory || flags.NArg() != 0 {
		return fmt.Errorf("usage: sandboxd -backend mock|firecracker -state-dir DIR [-max-instances 32]; mock provides NO isolation")
	}
	if *migrateLedger && (*backend != "" || *authFile != "" || *insecureMock || *firecrackerConfig != "" || *metricsEnabled) {
		return errors.New("offline migration cannot be combined with backend or authentication options")
	}
	if !*migrateLedger && ((*authFile == "" && !*insecureMock) || (*authFile != "" && *insecureMock)) {
		return &diagnostics.Fault{Reason: diagnostics.AuthMode}
	}
	if (*backend == "mock" && *firecrackerConfig != "") || (*backend == "firecracker" && (*firecrackerConfig == "" || *insecureMock)) {
		return errors.New("Firecracker requires -firecracker-config and -auth-file; insecure mode is mock-only")
	}
	var authenticator *access.Authenticator
	if *authFile != "" {
		var err error
		authenticator, err = access.Load(*authFile)
		if err != nil {
			return fmt.Errorf("load authentication configuration: %w", err)
		}
	}
	absDir, err := filepath.Abs(*stateDir)
	if err != nil {
		return err
	}
	if *migrateLedger {
		if _, err := os.Lstat(filepath.Join(absDir, "ledger")); err != nil {
			return fmt.Errorf("offline migration requires an existing ledger: %w", err)
		}
	}
	absDir, err = privatefile.EnsureDirectory(absDir)
	if err != nil {
		return err
	}
	info, err := os.Lstat(absDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state directory must be private (mode 0700): %s", absDir)
	}
	unlock, err := lockState(filepath.Join(absDir, "controller.lock"))
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return &diagnostics.Fault{Reason: diagnostics.StateLock, Cause: err}
		}
		return err
	}
	unfinishedCleanup := false
	defer func() { releaseStateLock(unlock, unfinishedCleanup) }()
	var diagnostic *diagnostics.Logger
	// Registered before control, session and manager defers: logging gets only
	// its own bounded wait AFTER those independent shutdown opportunities.
	defer func() {
		if diagnostic == nil {
			return
		}
		kind := diagnostics.ProcessStopped
		if retErr != nil {
			kind = diagnostics.ProcessFailed
		}
		diagnostic.Emit(kind, diagnostics.FailureReason(retErr))
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		if e := diagnostic.Close(ctx); e != nil {
			unfinishedCleanup = true
			retErr = errors.Join(retErr, diagnosticShutdownFault(e))
		}
	}()
	store, err := sandbox.NewFileStore(filepath.Join(absDir, "ledger"))
	if err != nil {
		return err
	}
	if *migrateLedger {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		report, err := store.Migrate(ctx)
		if err != nil {
			return fmt.Errorf("offline ledger migration unfinished; rerun after resolving the cause: %w", err)
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	controlStore, err := nodecontrol.OpenStore(absDir)
	if err != nil {
		return fmt.Errorf("load node admission control: %w", err)
	}
	admissionGate := sandbox.NewAdmissionGate(false)
	control, err := nodecontrol.New(controlStore, admissionGate)
	if err != nil {
		return err
	}
	// Registered before lifecycle defers: wait for any control writer only AFTER
	// Stop/Cleanup have had their independent shutdown opportunity.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := control.Close(ctx); e != nil {
			unfinishedCleanup = true
			diagnostic.Emit(diagnostics.ControlUnfinished, diagnostics.ReasonFor(e))
			retErr = errors.Join(retErr, fmt.Errorf("control mutation unfinished; retain state ownership: %w", e))
		}
	}()
	var driver sandbox.Driver
	metrics := &telemetry.Registry{}
	opts := sandbox.Options{AdmissionGate: admissionGate, Metrics: metrics, MaxInstances: *maxInstances, MaxRecords: *maxRecords, MaxTenantRecords: *maxTenantRecords, StopWorkers: *stopWorkers, CleanupWorkers: *cleanupWorkers, WorkQueueSize: *workQueueSize}
	writeTimeout := 10 * time.Second
	if *backend == "mock" {
		driver, err = sandbox.NewMockDriver(filepath.Join(absDir, "instances"))
	} else {
		var records []sandbox.Record
		records, err = store.Load()
		if err == nil {
			limits := sandbox.AdmissionLimits{MaxInstances: *maxInstances, MaxRecords: *maxRecords, MaxSessions: *maxSessions}
			if err = firecracker.ValidateAdmissionConfig(*firecrackerConfig, limits); err == nil {
				driver, err = firecracker.NewWithAdmission(absDir, *firecrackerConfig, records, limits)
			}
		}
		opts.PrepareTimeout, opts.StopTimeout, opts.CleanupTimeout = 30*time.Second, 5*time.Second, 10*time.Second
		writeTimeout = 40 * time.Second
	}
	if err != nil {
		return err
	}
	// No new API or lifecycle worker has started yet. Initialization validates
	// a bounded private ring or fails closed; startup storage I/O has no deadline
	// claim. Offline ledger migration never opens diagnostic state.
	diagnostic, err = diagnostics.Start(filepath.Join(absDir, "diagnostics"))
	if err != nil {
		return &diagnostics.Fault{Reason: diagnostics.DiagnosticsUnavailable, Cause: err}
	}
	started = true
	slog.SetDefault(slog.New(&diagnostics.Handler{Logger: diagnostic}))
	manager, err := sandbox.NewManager(store, driver, opts)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Close(ctx); err != nil {
			unfinishedCleanup = true
			diagnostic.Emit(diagnostics.CleanupUnfinished, diagnostics.ReasonFor(err))
			retErr = errors.Join(retErr, fmt.Errorf("cleanup unfinished: %w", err))
		}
	}()
	sessionStore, err := session.NewFileStore(filepath.Join(absDir, "sessions"))
	if err != nil {
		return err
	}
	sessions, err := session.New(manager, sessionStore, session.Options{Metrics: metrics, MaxSessions: *maxSessions, MaxTenantSessions: *maxTenantSessions, MaxAttempts: *sessionHistory})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sessions.Close(ctx); err != nil {
			unfinishedCleanup = true
			retErr = errors.Join(retErr, err)
			diagnostic.Emit(diagnostics.SessionUnfinished, diagnostics.ReasonFor(err))
		}
	}()

	var metricsErrors <-chan error
	if *metricsEnabled {
		observer, err := observability.Start(absDir, metrics, func() telemetry.Gauges {
			g := manager.Metrics()
			g.Sessions, g.SessionCapacity = sessions.Metrics()
			g.Diagnostics = diagnostic.Stats()
			return g
		})
		if err != nil {
			return err
		}
		defer observer.Close()
		metricsErrors = observer.Errors()
	}
	operator, err := nodecontrol.Start(absDir, control, manager.Stats)
	if err != nil {
		return err
	}
	defer func() {
		if e := operator.Stop(); e != nil {
			diagnostic.Emit(diagnostics.OperatorUnfinished, diagnostics.ReasonFor(e))
			retErr = errors.Join(retErr, e)
		}
	}()
	socket := filepath.Join(absDir, "api.sock")
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace a non-socket: %s", socket)
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socket)
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	handler, err := httpapi.NewConfigured(manager, httpapi.Options{Authenticator: authenticator, AllowUnauthenticatedMock: *insecureMock, Sessions: sessions})
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 2 * time.Second,
		// net/http's default error logger otherwise writes raw request/stack data
		// directly to inherited stderr, bypassing the closed diagnostic handler.
		ErrorLog:    log.New(io.Discard, "", 0),
		ReadTimeout: 10 * time.Second, WriteTimeout: writeTimeout,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
	}
	// Install termination handling before any request can be served. A health
	// response must not race the default SIGTERM action during startup.
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	if *backend == "mock" {
		slog.Warn("MOCK BACKEND: lifecycle simulation only; no sandbox isolation or host shell", "socket", socket)
	} else {
		slog.Warn("EXPERIMENTAL FIRECRACKER: production acceptance incomplete", "socket", socket)
	}
	defer server.Close()
	select {
	case err := <-operator.Errors():
		diagnostic.Emit(diagnostics.ListenerFailed, diagnostics.ReasonFor(err))
		return fmt.Errorf("operator listener failed: %w", err)
	case err := <-metricsErrors:
		diagnostic.Emit(diagnostics.ListenerFailed, diagnostics.ReasonFor(err))
		return fmt.Errorf("metrics listener failed: %w", err)
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			diagnostic.Emit(diagnostics.ListenerFailed, diagnostics.ReasonFor(err))
			return err
		}
	case <-signalCtx.Done():
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}
