//go:build linux

package hostdoctor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKVMIdentityModelRejectsAliasesOrdinaryAndOtherDevices(t *testing.T) {
	for _, s := range []unix.Stat_t{{Mode: unix.S_IFLNK, Rdev: unix.Mkdev(10, 232)}, {Mode: unix.S_IFREG, Rdev: unix.Mkdev(10, 232)}, {Mode: unix.S_IFCHR, Rdev: unix.Mkdev(1, 3)}, {Mode: unix.S_IFCHR, Rdev: unix.Mkdev(10, 200)}} {
		if kvmDevice(s) {
			t.Fatal("non-KVM device accepted")
		}
	}
	if !kvmDevice(unix.Stat_t{Mode: unix.S_IFCHR | 0660, Rdev: unix.Mkdev(10, 232)}) {
		t.Fatal("KVM device number model refused")
	}
}

func TestManagerVersionParserClosedAndBounded(t *testing.T) {
	for raw, want := range map[string]int{"249.11-0ubuntu3.23\n": 249, "254": 254, "255.4-1ubuntu8.18\n": 255, "260~rc1\n": 260} {
		if n, e := parseManagerVersion([]byte(raw)); e != nil || n != want {
			t.Fatal("valid running manager version refused", e)
		}
	}
	for _, raw := range []string{"", "0", "0255", "+255", "systemd 255", "255 garbage", "255\n255\n", "255\r\n", "255\x00", "255\n\n", "10000", "255.", strings.Repeat("x", 257)} {
		if _, e := parseManagerVersion([]byte(raw)); e == nil {
			t.Fatal("unconfirmed version accepted")
		}
	}
}

func TestControllerParserCompleteMissingAndMalformed(t *testing.T) {
	if v, e := parseControllers([]byte("cpuset cpu io memory pids hugetlb\n")); e != nil || len(v) != 0 {
		t.Fatal("complete inventory refused", e)
	}
	if v, e := parseControllers([]byte("cpu memory\n")); e != nil || !reflect.DeepEqual(v, []string{"io", "pids"}) {
		t.Fatal("missing controller projection changed", e)
	}
	if v, e := parseControllers([]byte("\n")); e != nil || len(v) != 4 {
		t.Fatal("empty kernel inventory was not reported missing")
	}
	for _, raw := range []string{"", "cpu", "cpu cpu io memory pids\n", "cpu\nio memory pids\n", "cpu\r io memory pids\n", "cpu\x00 io memory pids\n", "CPU io memory pids\n", strings.Repeat("x", 4097)} {
		if _, e := parseControllers([]byte(raw)); e == nil {
			t.Fatal("malformed controller inventory accepted")
		}
	}
}

func TestOnlyFixedLocalManagerQueryAndEnvironment(t *testing.T) {
	if !reflect.DeepEqual(managerArgs(), []string{"--system", "--no-pager", "--no-ask-password", "show", "--property=Version", "--value"}) {
		t.Fatal("query gained a unit, mutation, host or caller argument")
	}
	for _, key := range []string{"PATH", "SYSTEMD_HOST", "SYSTEMD_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS", "LD_PRELOAD", "SYSTEMD_PAGER"} {
		t.Setenv(key, "PRIVATE_SECRET_DO_NOT_USE")
	}
	if env := strings.Join(managerEnvironment(), "\n"); strings.Contains(env, "PRIVATE_SECRET") || strings.Contains(env, "SYSTEMD_HOST") || strings.Contains(env, "BUS_ADDRESS") || strings.Contains(env, "LD_PRELOAD") {
		t.Fatal("ambient host/loader/command selection accepted")
	}
	a := managerArgs()
	a[0] = "start"
	if managerArgs()[0] != "--system" {
		t.Fatal("mutable query args shared across callers")
	}
}

func TestBoundedReadAndCommandBuffers(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "modeled-kernel-file")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.WriteString("12345"); e != nil {
		t.Fatal(e)
	}
	f.Seek(0, 0)
	if _, e = boundedRead(f, 4); e == nil {
		t.Fatal("oversized file accepted")
	}
	f.Seek(0, 0)
	if b, e := boundedRead(f, 5); e != nil || string(b) != "12345" {
		t.Fatal("exact file bound rejected")
	}
	b := &limitedBuffer{limit: 4}
	// Embedding bytes.Buffer would promote ReaderFrom and allow io.Copy in
	// os/exec to bypass Write's limit. This writer must expose no such shortcut.
	if _, ok := any(b).(io.ReaderFrom); ok {
		t.Fatal("command buffer exposes a limit-bypassing ReaderFrom")
	}
	if _, e = b.Write([]byte("1234")); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Write([]byte("5")); e == nil || b.Len() != 4 {
		t.Fatal("command output became unbounded")
	}
}

// Only an owned Go test child is executed; never install/start/stop a service.
func TestDoctorQueryChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--doctor-test-child" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "version":
		fmt.Fprint(os.Stdout, "255.4\n")
	case "stderr":
		fmt.Fprint(os.Stderr, "PRIVATE_UNTRUSTED_ERROR")
	case "oversized":
		os.Stdout.Write(bytes.Repeat([]byte{'x'}, 2048))
	case "wait":
		time.Sleep(10 * time.Second)
	default:
		os.Exit(3)
	}
	os.Exit(0)
}

func TestRealOwnedChildQueryOutputFailureAndDeadline(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"version", "stderr", "oversized", "wait"} {
		t.Run(mode, func(t *testing.T) {
			limit := 3 * time.Second
			if mode == "wait" {
				limit = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestDoctorQueryChild$", "--doctor-test-child", mode)
			// The testing package requires -- before its non-flag helper arguments.
			cmd.Args = []string{exe, "-test.run=^TestDoctorQueryChild$", "--", "--doctor-test-child", mode}
			raw, e := runQuery(cmd)
			if mode == "version" {
				if e != nil || string(raw) != "255.4\n" {
					t.Fatal("owned child query failed", e)
				}
			} else if e == nil || len(raw) != 0 {
				t.Fatal("error/output/timeout accepted or leaked")
			}
			if cmd.ProcessState == nil {
				t.Fatal("query child not reaped")
			}
		})
	}
}
