//go:build linux

// xandbox-agent runs only inside the project guest image, never on the host.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/123123213weqw/Xandbox/internal/guest"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/mdlayher/vsock"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--build-info" {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"protocol": guestwire.Version, "go_version": runtime.Version()})
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
	executor, ref, bootID, err := guest.NewExecutor()
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
	server := &guest.Server{Ref: ref, BootID: bootID, Runner: executor}
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
