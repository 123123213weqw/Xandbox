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

// Hide WriterTo so io.Copy must exercise its destination's actual method set.
type managerReaderOnly struct{ io.Reader }

func TestManagerWriterCopyBound(t *testing.T) {
	b := &limitedBuffer{limit: 8}
	n, e := io.Copy(b, managerReaderOnly{strings.NewReader(strings.Repeat("x", 64))})
	if e == nil || n > 8 || b.Len() > 8 {
		t.Fatal("io.Copy bypassed the manager output bound")
	}
}

// This child only emits bounded synthetic bytes. It never invokes systemctl,
// opens a host control socket or changes service state.
func TestManagerOutputChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--manager-output-child" {
		return
	}
	stream := os.Stdout
	if os.Args[len(os.Args)-1] == "stderr" {
		stream = os.Stderr
	}
	if _, e := io.WriteString(stream, strings.Repeat("x", 65536)); e != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func managerOutputChild(ctx context.Context, t *testing.T, mode string) *exec.Cmd {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	return exec.CommandContext(ctx, exe, "-test.run=^TestManagerOutputChild$", "--", "--manager-output-child", mode)
}

func TestManagerWriterExecCopyBound(t *testing.T) {
	for _, mode := range []string{"stdout", "stderr"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := managerOutputChild(ctx, t, mode)
			out, errout := &limitedBuffer{limit: 16384}, &limitedBuffer{limit: 4096}
			cmd.Stdout, cmd.Stderr = out, errout
			e := cmd.Run()
			if ctx.Err() != nil || cmd.ProcessState == nil {
				t.Fatal("owned child was not reaped before its guard deadline")
			}
			if e == nil || out.Len() > 16384 || errout.Len() > 4096 {
				t.Fatal("os/exec bypassed the manager output bound")
			}
		})
	}
}
