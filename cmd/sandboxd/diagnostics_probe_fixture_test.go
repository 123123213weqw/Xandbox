//go:build xandbox_diagnostics_fixture && (linux || darwin)

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"golang.org/x/sys/unix"
)

// This helper exists only in an opt-in TEST executable. It calls the ordinary
// runArgs, retaining its real deadlines, ring barriers, errors and state lock.
// A separate nonblocking owned pipe reports a closed enum AFTER runArgs returns;
// inherited stdout/stderr remain full and undrained. This is not the ordinary
// daemon binary and cannot qualify or retrospectively explain an earlier CI run.
const diagnosticProbeFD = "XANDBOX_DIAGNOSTICS_PROBE_FD"

func diagnosticProbeCode(err error) byte {
	if err == nil {
		return 0
	}
	pending := errors.Is(err, diagnostics.ErrPending)
	write := errors.Is(err, diagnostics.ErrWrite)
	switch {
	case pending && !write:
		return 1
	case write && !pending:
		return 2
	default:
		return 3
	}
}

func diagnosticProbeReceipt(fd int, code byte) bool {
	if fd < 3 || code > 3 {
		return false
	}
	var st unix.Stat_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 || flags&unix.O_ACCMODE != unix.O_WRONLY || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return false
	}
	// Do not leak this test-only observer capability to a later exec.
	syscall.CloseOnExec(fd)
	frame := []byte{'X', code}
	for range 3 {
		n, err := unix.Write(fd, frame)
		if err == unix.EINTR {
			continue
		}
		return err == nil && n == len(frame)
	}
	return false
}

func TestDiagnosticsProbeProcessHelper(t *testing.T) {
	value := os.Getenv(diagnosticProbeFD)
	if value == "" {
		t.Skip("opt-in owned process probe only")
	}
	fd, err := strconv.Atoi(value)
	if err != nil || fd < 3 {
		os.Exit(2)
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		os.Exit(2)
	}
	err = runArgs(args)
	if !diagnosticProbeReceipt(fd, diagnosticProbeCode(err)) {
		os.Exit(2)
	}
	if err != nil {
		os.Exit(processExitCode(err))
	}
	os.Exit(0)
}

type diagnosticProbeUnrenderable struct{}

func (diagnosticProbeUnrenderable) Error() string { panic("must not render diagnostic cause") }

func TestDiagnosticsProbeUnitClosedCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code byte
	}{
		{nil, 0}, {diagnostics.ErrPending, 1}, {diagnostics.ErrWrite, 2},
		{&diagnostics.Fault{Reason: diagnostics.DiagnosticsUnavailable, Cause: diagnostics.ErrPending}, 1},
		{errors.Join(diagnostics.ErrWrite, diagnosticProbeUnrenderable{}), 2},
		{errors.Join(diagnostics.ErrPending, diagnostics.ErrWrite), 3},
		{diagnosticProbeUnrenderable{}, 3},
	} {
		if diagnosticProbeCode(tc.err) != tc.code {
			t.Fatal("closed code mismatch")
		}
	}
}

func TestDiagnosticsProbeUnitOwnedNonblockingPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd := int(w.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	if !diagnosticProbeReceipt(fd, 2) {
		t.Fatal("owned pipe receipt failed")
	}
	var got [2]byte
	if n, err := r.Read(got[:]); err != nil || n != 2 || got != [2]byte{'X', 2} {
		t.Fatal("receipt not fixed frame")
	}
}

func TestDiagnosticsProbeUnitRejectsOtherDescriptors(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd := int(w.Fd())
	if diagnosticProbeReceipt(fd, 0) || diagnosticProbeReceipt(1, 0) || diagnosticProbeReceipt(-1, 0) {
		t.Fatal("blocking or inherited stream accepted")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	if diagnosticProbeReceipt(fd, 255) || diagnosticProbeReceipt(int(r.Fd()), 0) {
		t.Fatal("unknown code or read descriptor accepted")
	}
	f, err := os.CreateTemp(t.TempDir(), "not-a-pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	regular := int(f.Fd())
	if err := unix.SetNonblock(regular, true); err != nil {
		t.Fatal(err)
	}
	if diagnosticProbeReceipt(regular, 0) {
		t.Fatal("regular file accepted")
	}
}

func TestDiagnosticsProbeUnitFullPipeNeverWaits(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd := int(w.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	var payload [4096]byte
	full := false
	for range 512 {
		if _, err := unix.Write(fd, payload[:]); err == unix.EAGAIN {
			full = true
			break
		} else if err != nil {
			t.Fatal("test pipe fill unavailable")
		}
	}
	if !full || diagnosticProbeReceipt(fd, 1) {
		t.Fatal("full pipe acknowledged or test fill bound exhausted")
	}
}

func TestDiagnosticsExitProcessHelper(t *testing.T) {
	mode := os.Getenv("XANDBOX_DIAGNOSTICS_EXIT_CASE")
	if mode == "" {
		t.Skip("opt-in closed exit unit child only")
	}
	var err error
	switch mode {
	case "clean":
	case "pending":
		err = diagnosticShutdownFault(diagnostics.ErrPending)
	case "write":
		err = diagnosticShutdownFault(diagnostics.ErrWrite)
	case "generic":
		err = diagnosticProbeUnrenderable{}
	case "unqualified":
		err = diagnostics.ErrPending
	case "bootstrap":
		err = &bootstrapFailure{reason: diagnostics.AuthMode, cause: diagnosticShutdownFault(diagnostics.ErrPending)}
	default:
		os.Exit(2)
	}
	os.Exit(processExitCode(err))
}

// Actual owned child exit statuses, with both inherited streams full. This
// tests the production decision function, not a real stalled fsync/Close.
func TestDiagnosticsProbeUnitProcessExitStatuses(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd, reader := int(w.Fd()), int(r.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	payload := [1024]byte{}
	for i := range payload {
		payload[i] = 'x'
	}
	filled, full := 0, false
	for range 4096 {
		n, err := unix.Write(fd, payload[:])
		if n > 0 {
			filled += n
		}
		if err == unix.EAGAIN {
			full = true
			break
		}
		if err != nil {
			t.Fatal("inherited pipe fill failed")
		}
	}
	if !full || unix.SetNonblock(fd, false) != nil {
		t.Fatal("full blocking inherited stream unavailable")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("owned test executable unavailable")
	}
	for _, tc := range []struct {
		mode string
		code int
	}{{"clean", 0}, {"pending", 75}, {"write", 74}, {"generic", 1}, {"unqualified", 1}, {"bootstrap", 1}} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestDiagnosticsExitProcessHelper$")
		cmd.Env = append(os.Environ(), "XANDBOX_DIAGNOSTICS_EXIT_CASE="+tc.mode)
		cmd.Stdout, cmd.Stderr = w, w
		result := cmd.Run()
		timedOut := ctx.Err() != nil
		cancel()
		if timedOut {
			t.Fatal("closed exit waited on inherited streams")
		}
		got := 0
		if result != nil {
			var exited *exec.ExitError
			if !errors.As(result, &exited) {
				t.Fatal("owned child did not return an exit status")
			}
			got = exited.ExitCode()
		}
		if got != tc.code {
			t.Fatal("actual process status mismatch", got, tc.code)
		}
	}
	if w.Close() != nil || unix.SetNonblock(reader, true) != nil {
		t.Fatal("closed process pipe unavailable")
	}
	total := 0
	var buffer [4096]byte
	for {
		n, err := unix.Read(reader, buffer[:])
		if err != nil {
			t.Fatal("closed inherited pipe read failed")
		}
		for _, b := range buffer[:n] {
			if b != 'x' {
				t.Fatal("closed exit emitted inherited-stream output")
			}
		}
		total += n
		if n == 0 {
			break
		}
	}
	if total != filled {
		t.Fatal("inherited pipe changed")
	}
}
