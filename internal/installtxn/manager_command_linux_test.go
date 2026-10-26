//go:build linux

package installtxn

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestManagerWriterHasNoBypassMethods(t *testing.T) {
	b := &limitedBuffer{limit: 8}
	if _, ok := any(b).(io.ReaderFrom); ok {
		t.Fatal("manager writer exposes a limit-bypassing ReaderFrom")
	}
	if _, ok := any(b).(io.StringWriter); ok {
		t.Fatal("manager writer exposes an unreviewed alternate write path")
	}
	for _, limit := range []int{0, 8} {
		b = &limitedBuffer{limit: limit}
		if n, e := b.Write([]byte(strings.Repeat("x", limit))); e != nil || n != limit || b.Len() != limit {
			t.Fatal("exact output bound refused")
		}
		if n, e := b.Write([]byte("PRIVATE_OVERFLOW")); e == nil || n != 0 || b.Len() != limit {
			t.Fatal("overflow changed saved output")
		}
	}
	if _, e := (&limitedBuffer{limit: -1}).Write(nil); e == nil {
		t.Fatal("invalid internal limit accepted")
	}
}

// Only this test executable runs. No service or trusted OS command is replaced.
func TestManagerCaptureChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--manager-capture-child" {
		return
	}
	var e error
	switch os.Args[len(os.Args)-1] {
	case "empty":
	case "exact":
		_, e = io.WriteString(os.Stdout, strings.Repeat("x", 16384))
	case "stdout-overflow":
		_, e = io.WriteString(os.Stdout, strings.Repeat("x", 16385))
	case "stderr":
		_, e = io.WriteString(os.Stderr, "PRIVATE_MANAGER_STDERR")
	case "stderr-overflow":
		_, e = io.WriteString(os.Stderr, strings.Repeat("x", 4097))
	case "failed":
		io.WriteString(os.Stdout, "PRIVATE_PARTIAL_MANAGER_OUTPUT")
		os.Exit(7)
	case "wait":
		time.Sleep(10 * time.Second)
	default:
		os.Exit(3)
	}
	if e != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestManagerCaptureActualChildClosedResultsAndReap(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"empty", "exact", "stdout-overflow", "stderr", "stderr-overflow", "failed", "wait"} {
		t.Run(mode, func(t *testing.T) {
			limit := 5 * time.Second
			if mode == "wait" {
				limit = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestManagerCaptureChild$", "--", "--manager-capture-child", mode)
			raw, e := captureManagerOutput(cmd)
			if cmd.ProcessState == nil {
				t.Fatal("owned manager test child not reaped")
			}
			if mode == "empty" || mode == "exact" {
				want := ""
				if mode == "exact" {
					want = strings.Repeat("x", 16384)
				}
				if e != nil || string(raw) != want {
					t.Fatal("bounded successful output refused")
				}
			} else if e != ErrPlatform || len(raw) != 0 {
				t.Fatal("command error, stderr, overflow or cancellation leaked output or became success")
			}
		})
	}
}
