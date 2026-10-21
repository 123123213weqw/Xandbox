package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/123123213weqw/Xandbox/internal/httpapi"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func main() {
	if err := run(); err != nil {
		slog.Error("sandboxd failed", "error", err)
		os.Exit(1)
	}
}

func run() (retErr error) {
	stateDir := flag.String("state-dir", "", "required private state directory")
	backend := flag.String("backend", "", "required: mock (simulation only)")
	maxInstances := flag.Int("max-instances", 32, "maximum allocated, including unreclaimed instances")
	flag.Parse()
	if *stateDir == "" || *backend != "mock" || *maxInstances < 1 || flag.NArg() != 0 {
		return fmt.Errorf("usage: sandboxd -backend mock -state-dir DIR [-max-instances 32]; mock provides NO isolation")
	}
	absDir, err := filepath.Abs(*stateDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(absDir, 0700); err != nil {
		return err
	}
	info, err := os.Stat(absDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state directory must be private (mode 0700): %s", absDir)
	}
	unlock, err := lockState(filepath.Join(absDir, "controller.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	store, err := sandbox.NewFileStore(filepath.Join(absDir, "ledger"))
	if err != nil {
		return err
	}
	driver, err := sandbox.NewMockDriver(filepath.Join(absDir, "instances"))
	if err != nil {
		return err
	}
	manager, err := sandbox.NewManager(store, driver, sandbox.Options{MaxInstances: *maxInstances})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Close(ctx); err != nil {
			slog.Error("cleanup unfinished; restart with the same state directory to recover", "error", err)
			retErr = errors.Join(retErr, fmt.Errorf("cleanup unfinished: %w", err))
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
	server := &http.Server{
		Handler: httpapi.New(manager), ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	slog.Warn("MOCK BACKEND: lifecycle simulation only; no sandbox isolation or host shell", "socket", socket)
	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-signalCtx.Done():
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}
