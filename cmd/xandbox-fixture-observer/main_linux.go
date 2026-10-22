//go:build linux && xandbox_guest_fixture

// Fixture-only, read-only guest diagnostics. Excluded from all default builds
// and production images. No task argv, arbitrary path, write or reset operation.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/fixturewire"
	"github.com/123123213weqw/Xandbox/internal/guest"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/mdlayher/vsock"
)

func main() {
	marker, e := os.ReadFile("/etc/xandbox-fixture-observer")
	if e != nil || string(marker) != "Xandbox fixture observer v1\n" || os.Geteuid() != 0 {
		os.Exit(126)
	}
	if pristine, e := guest.PristineBoot(); e != nil || !pristine {
		os.Exit(126)
	}
	agent, e := os.ReadFile("/usr/bin/xandbox-agent")
	if e != nil {
		os.Exit(126)
	}
	wanted := sha256.Sum256(agent)
	listener, e := vsock.Listen(fixturewire.Port, nil)
	if e != nil {
		os.Exit(1)
	}
	defer listener.Close()
	seen := map[string]bool{}
	for {
		c, e := listener.Accept()
		if e != nil {
			os.Exit(1)
		}
		peer, ok := c.RemoteAddr().(*vsock.Addr)
		if !ok || peer.ContextID != vsock.Host {
			c.Close()
			continue
		}
		// Serial and bounded; diagnostics must not create an unbounded worker pool.
		func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			var q fixturewire.Request
			if guestwire.Read(c, 1024, &q) != nil || q.Version != 1 || q.Operation != "inspect" || len(q.ExpectedBootID) > 36 {
				return
			}
			out := fixturewire.Response{Version: 1}
			_, e = os.Lstat("/run/xandbox-init/claimed")
			out.Claimed = e == nil
			_, e = os.Lstat("/run/xandbox-init/receipt.json")
			out.Receipt = e == nil
			if s, e := os.Lstat("/etc/machine-id"); e == nil {
				out.MachineIDDirectory = s.IsDir()
			}
			if b, e := os.ReadFile("/proc/sys/kernel/random/boot_id"); e == nil && q.ExpectedBootID != "" {
				out.BootMatches = strings.TrimSpace(string(b)) == q.ExpectedBootID
			}
			if b, e := os.ReadFile("/proc/self/mountinfo"); e == nil {
				for _, line := range strings.Split(string(b), "\n") {
					parts := strings.Fields(line)
					if len(parts) > 6 && parts[4] == "/proc/sys/kernel/random/boot_id" {
						out.BootReadOnlyBind = strings.Contains(","+parts[5]+",", ",ro,")
					}
				}
			}
			entries, _ := os.ReadDir("/proc")
			for _, entry := range entries {
				if _, e := strconv.Atoi(entry.Name()); e != nil {
					continue
				}
				exe, e := os.Readlink("/proc/" + entry.Name() + "/exe")
				if e != nil || exe != "/usr/bin/xandbox-agent" {
					continue
				}
				data, e := os.ReadFile("/proc/" + entry.Name() + "/exe")
				if e != nil {
					continue
				}
				h := sha256.Sum256(data)
				if h != wanted {
					continue
				}
				stat, e := os.ReadFile("/proc/" + entry.Name() + "/stat")
				if e != nil {
					continue
				}
				// PID plus kernel starttime; never expose either in a diagnostic response.
				tail := string(stat)
				at := strings.LastIndex(tail, ") ")
				if at < 0 {
					continue
				}
				fields := strings.Fields(tail[at+2:])
				if len(fields) <= 19 {
					continue
				}
				seen[entry.Name()+":"+fields[19]+":"+hex.EncodeToString(h[:])] = true
			}
			out.AgentGenerations = len(seen)
			_ = guestwire.Write(c, 2048, out)
		}()
	}
}
