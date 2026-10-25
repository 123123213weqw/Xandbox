//go:build linux && xandbox_host_fixture

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/privatefile"
)

// This separate fresh L1 disk is ordinary writable ext4 without project quota.
// Never disable quota on the enforced profile, a bound backend or any L0 mount.
func (n *node) quotaUnenforced(ctx context.Context) (out map[string]any, err error) {
	if e := requireNode(); e != nil {
		return nil, e
	}
	if !n.quotaDriver || n.quotaSnapshot || n.process != nil {
		return nil, errors.New("fresh fixed driver rejection profile required")
	}
	for _, path := range []string{"/srv/state/firecracker", "/srv/r", "/srv/fixture/unenforced.log"} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return nil, errors.New("refuse existing backend resources")
		}
	}
	b, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return nil, e
	}
	found := 0
	for _, line := range strings.Split(string(b), "\n") {
		sides := strings.Split(line, " - ")
		if len(sides) != 2 {
			continue
		}
		left, right := strings.Fields(sides[0]), strings.Fields(sides[1])
		if len(left) >= 6 && left[4] == "/srv" {
			if len(right) != 3 || right[0] != "ext4" || !quotaOption(left[5], "rw") || quotaOption(right[2], "prjquota") {
				return nil, errors.New("fresh unenforced writable ext4 prerequisite not met")
			}
			found++
		}
	}
	if found != 1 {
		return nil, errors.New("ambiguous unenforced ext4 prerequisite")
	}
	log, e := os.OpenFile("/srv/fixture/unenforced.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	defer func() {
		if err != nil {
			f, e := os.Open("/srv/fixture/unenforced.log")
			if e == nil {
				io.CopyN(os.Stderr, f, 4096)
				f.Close()
			}
			time.Sleep(time.Second)
		}
	}()
	childCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c := exec.CommandContext(childCtx, "/usr/bin/xandbox-host-fixture", "-mode", "quota-daemon-drop")
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	c.Stdout, c.Stderr = log, log
	runErr := c.Run()
	if runErr == nil || childCtx.Err() != nil {
		return nil, errors.New("unenforced ordinary daemon did not reject within bound")
	}
	b, e = privatefile.Read("/srv/fixture/unenforced.log", 65536)
	if e != nil {
		return nil, e
	}
	if !exactStartupRefusal(runErr, b, "quota requires the exact writable ext4 mount with enforced prjquota") {
		return nil, errors.New("specific ordinary mount enforcement rejection missing")
	}
	for _, path := range []string{"/srv/state/api.sock", "/srv/state/firecracker", "/srv/r/j"} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return nil, errors.New("unenforced daemon created API or generation ownership")
		}
	}
	entries, e := os.ReadDir(nodeGroup)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, errors.New("unenforced daemon created generation cgroup")
		}
	}
	return map[string]any{"ordinary_daemon": true, "fresh_writable_ext4_without_project_enforcement": true, "specific_enforcement_startup_rejection_checked": true, "no_api_or_backend_ownership_or_generation_domain": true, "fixed_child_reaped": true, "no_quota_on_off_or_mount_policy_mutation": true, "l2_vms_started": 0}, nil
}
