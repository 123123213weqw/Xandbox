//go:build linux || darwin

package sandbox

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

const resultCrashCutMarker byte = 0x6b

// This is only the selected-cut witness, not proof of death. The caller must
// ALSO require the original exact syscall.WaitStatus SIGKILL, then run all the
// original fresh-store and byte-preservation assertions. A watchdog kill fails
// this predicate even when the cut was acknowledged before the deadline.
func resultCrashCutWitness(contextErr error, ack []byte, readErr error) bool {
	return contextErr == nil && readErr == nil && len(ack) == 1 && ack[0] == resultCrashCutMarker
}

func TestResultStoreCrashCutWitnessRefusesWatchdogAndMissingAck(t *testing.T) {
	for _, tc := range []struct {
		name       string
		contextErr error
		ack        []byte
		readErr    error
		want       bool
	}{
		{"selected-cut-only", nil, []byte{0x6b}, nil, true},
		{"watchdog-after-ack", context.DeadlineExceeded, []byte{0x6b}, nil, false},
		{"canceled-after-ack", context.Canceled, []byte{0x6b}, nil, false},
		{"missing-ack", nil, nil, nil, false},
		{"empty-ack", nil, []byte{}, nil, false},
		{"wrong-ack", nil, []byte{0x6a}, nil, false},
		{"duplicate-ack", nil, []byte{0x6b, 0x6b}, nil, false},
		{"excess-ack", nil, []byte{0x6b, 0x00, 0x00}, nil, false},
		{"read-error-after-ack", nil, []byte{0x6b}, errors.New("witness read failed"), false},
		{"unexpected-EOF", nil, []byte{0x6b}, io.ErrUnexpectedEOF, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resultCrashCutWitness(tc.contextErr, tc.ack, tc.readErr); got != tc.want {
				t.Fatalf("selected-cut witness = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestResultStoreCrashCutWatchdogOwnedHelper(t *testing.T) {
	if os.Getenv("XANDBOX_RESULT_WITNESS_WATCHDOG_ONLY") != "owned-parent" {
		t.Skip("owned watchdog witness helper")
	}
	ack := os.NewFile(3, "result-watchdog-negative-witness")
	if n, err := ack.Write([]byte{0x6b}); err != nil || n != 1 {
		os.Exit(16)
	}
	if ack.Close() != nil {
		os.Exit(17)
	}
	// Deliberately no self-Kill: only this test's parent cancellation may kill
	// this owned child. A real SIGKILL with a valid ACK must still be refused.
	for {
		time.Sleep(time.Hour)
	}
}

func TestResultStoreCrashCutActualWatchdogSIGKILLCannotPassWitness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	deadline, ok := ctx.Deadline()
	if !ok || reader.SetReadDeadline(deadline) != nil {
		t.Fatal("watchdog negative witness has no bounded read")
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestResultStoreCrashCutWatchdogOwnedHelper$")
	cmd.ExtraFiles = []*os.File{writer}
	cmd.Env = append(os.Environ(), "XANDBOX_RESULT_WITNESS_WATCHDOG_ONLY=owned-parent")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	closeErr := writer.Close()
	ack, ackErr := io.ReadAll(io.LimitReader(reader, 2))
	beforeCancel := ctx.Err()
	cancel()
	waitErr := cmd.Wait() // Reap before any fatal assertion, including bad ACK.
	if closeErr != nil || beforeCancel != nil || ackErr != nil || !bytesEqualCrashMarker(ack) {
		t.Fatal("negative control did not acknowledge before owned cancellation")
	}
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) {
		t.Fatal("watchdog control did not die", waitErr)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("watchdog control was not actual SIGKILL", waitErr)
	}
	if !errors.Is(ctx.Err(), context.Canceled) || resultCrashCutWitness(ctx.Err(), ack, ackErr) {
		t.Fatal("actual watchdog SIGKILL accepted as selected-cut crash")
	}
}

func bytesEqualCrashMarker(b []byte) bool {
	return len(b) == 1 && b[0] == 0x6b
}
