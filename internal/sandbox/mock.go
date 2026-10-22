package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MockDriver simulates bounded tool calls. It NEVER launches a host command,
// interprets shell syntax, or claims CPU/memory/network isolation.
type MockDriver struct{ dir string }

func NewMockDriver(dir string) (*MockDriver, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &MockDriver{dir: dir}, nil
}

func (*MockDriver) Name() string { return "mock" }

func (d *MockDriver) instanceDir(ref Ref) (string, error) {
	if !validRef(ref) {
		return "", fmt.Errorf("%w: invalid runtime identity", ErrInvalid)
	}
	return filepath.Join(d.dir, ref.ID+"-"+ref.Generation), nil
}

func (d *MockDriver) Prepare(ctx context.Context, ref Ref, _ Preparation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := d.instanceDir(ref)
	if err != nil {
		return err
	}
	return os.Mkdir(path, 0700)
}

func (d *MockDriver) Exec(ctx context.Context, ref Ref, req ExecRequest, limit int) (Output, error) {
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	path, err := d.instanceDir(ref)
	if err != nil {
		return Output{}, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return Output{}, err
	}
	defer root.Close()
	var out Output
	switch req.Argv[0] {
	case "echo":
		out.Stdout = strings.Join(req.Argv[1:], " ") + "\n"
	case "sleep":
		if len(req.Argv) != 2 {
			return Output{}, fmt.Errorf("sleep expects one duration, e.g. 100ms")
		}
		duration, err := time.ParseDuration(req.Argv[1])
		if err != nil || duration < 0 || duration > time.Hour {
			return Output{}, fmt.Errorf("invalid sleep duration")
		}
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return Output{}, ctx.Err()
		case <-timer.C:
		}
	case "write":
		if len(req.Argv) != 3 {
			return Output{}, fmt.Errorf("write expects a relative file path and content")
		}
		f, err := root.OpenFile(req.Argv[1], os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return Output{}, err
		}
		_, writeErr := io.WriteString(f, req.Argv[2])
		closeErr := f.Close()
		if writeErr != nil {
			return Output{}, writeErr
		}
		if closeErr != nil {
			return Output{}, closeErr
		}
	case "read":
		if len(req.Argv) != 2 {
			return Output{}, fmt.Errorf("read expects one relative file path")
		}
		f, err := root.Open(req.Argv[1])
		if err != nil {
			return Output{}, err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return Output{}, err
		}
		if !info.Mode().IsRegular() {
			return Output{}, fmt.Errorf("read only supports regular files")
		}
		data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
		if err != nil {
			return Output{}, err
		}
		out.Stdout = string(data)
	case "fail":
		out.ExitCode = 1
		out.Stderr = "simulated command failure\n"
	default:
		return Output{}, fmt.Errorf("mock supports only echo, sleep, write, read, fail; no host shell is executed")
	}
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	if len(out.Stdout) > limit {
		out.Stdout = out.Stdout[:limit]
		out.Truncated = true
	}
	if len(out.Stderr) > limit {
		out.Stderr = out.Stderr[:limit]
		out.Truncated = true
	}
	return out, nil
}

// The mock has no guest processes; Manager cancels and drains its tracked calls.
func (*MockDriver) Stop(ctx context.Context, _ Ref) error { return ctx.Err() }

func (d *MockDriver) Cleanup(ctx context.Context, ref Ref) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := d.instanceDir(ref)
	if err != nil {
		return err
	}
	return os.RemoveAll(path)
}

func (d *MockDriver) RefreshLease(ref Ref) error { return nil }
