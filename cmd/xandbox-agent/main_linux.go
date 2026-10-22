//go:build linux

// xandbox-agent runs only inside the project guest image, never on the host.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/123123213weqw/Xandbox/internal/guest"
	"github.com/123123213weqw/Xandbox/internal/guestinit"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/mdlayher/vsock"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--build-info" {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"protocol": guestwire.Version, "pristine_bootstrap_protocol": guestinit.Version, "go_version": runtime.Version()})
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--run-child" {
		if err := guest.RunChild(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "guest child launch rejected")
			os.Exit(126)
		}
		return
	}
	os.Clearenv()
	os.Setenv("PATH", "/bin:/usr/bin")

	var executor *guest.Executor
	var ref sandbox.Ref
	var bootID, epoch string
	var err error
	if len(os.Args) == 2 && os.Args[1] == "--initialized" {
		executor, ref, bootID, epoch, err = guest.NewInitializedExecutor()
	} else if len(os.Args) != 1 {
		err = fmt.Errorf("unknown guest mode")
	} else {
		var pristine bool
		pristine, err = guest.PristineBoot()
		if err == nil && pristine {
			servePristine()
			return
		}
		if err == nil {
			executor, ref, bootID, err = guest.NewExecutor()
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "guest initialization failed:", err)
		os.Exit(1)
	}
	listener, err := vsock.Listen(guestwire.Port, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "guest vsock listen failed")
		os.Exit(1)
	}
	defer listener.Close()
	server := &guest.Server{InitializationHash: epoch, Ref: ref, BootID: bootID, Runner: executor}
	slots := make(chan struct{}, 16)
	for {
		conn, err := listener.Accept()
		if err != nil {
			os.Exit(1)
		}
		peer, ok := conn.RemoteAddr().(*vsock.Addr)
		if !ok || peer.ContextID != vsock.Host {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); server.ServeConn(conn, true) }()
		default:
			conn.Close()
		}
	}
}

// Pristine mode has no normal health/exec listener and never accepts task argv.
func servePristine() {
	listener, err := vsock.Listen(guestinit.Port, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pristine vsock listen failed")
		os.Exit(1)
	}
	defer listener.Close()
	gate := guestinit.New(guest.InitializeAndExec)
	slots := make(chan struct{}, 16)
	for {
		conn, err := listener.Accept()
		if err != nil {
			os.Exit(1)
		}
		peer, ok := conn.RemoteAddr().(*vsock.Addr)
		if !ok || peer.ContextID != vsock.Host {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); gate.ServeConn(conn, true) }()
		default:
			conn.Close()
		}
	}
}
