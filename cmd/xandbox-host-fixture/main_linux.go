//go:build linux && xandbox_host_fixture

// TEST ONLY. A fixed nested-host acceptance fixture, never a production daemon
// or tenant RPC. Default builds deliberately exclude this entire command.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	mode := flag.String("mode", "", "internal test-only mode")
	config := flag.String("config", "", "root-owned fixture launch policy")
	flag.Parse()
	var err error
	switch *mode {
	case "launch":
		err = launch(*config)
	case "qemu-child":
		err = qemuChild(*config)
	case "node":
		err = runNode()
	case "node-quota-snapshot":
		err = runNodeAllProfiles(false, false, false, true)
	case "node-quota-driver":
		err = runNodeProfiles(false, false, true)
	case "quota-daemon-drop", "quota-snapshot-daemon-drop":
		if *config != "" || flag.NArg() != 0 {
			err = fmt.Errorf("quota daemon accepts no parameters")
		} else {
			if *mode == "quota-snapshot-daemon-drop" {
				err = runQuotaDaemonCapacity(2)
			} else {
				err = runQuotaDaemon()
			}
		}
	case "node-quota":
		err = runNodeOptions(false, true)
	case "quota-drop", "quota-limited":
		if *config != "" || flag.NArg() != 0 {
			err = fmt.Errorf("quota worker accepts no parameters")
		} else {
			err = quotaWorker(*mode)
		}
	case "node-io":
		err = runNodeProfile(true)
	default:
		err = fmt.Errorf("invalid fixture mode")
	}
	if err != nil {
		// This stream is PRIVATE operator diagnostics, never public evidence.
		fmt.Fprintln(os.Stderr, "host fixture failed:", err)
		os.Exit(1)
	}
}
