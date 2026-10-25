//go:build linux

package releasestore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func crashInputs(_ context.Context, m Manifest) ([]*os.File, error) {
	var files []*os.File
	for _, v := range m.Files {
		f, e := os.Open(v.Source)
		if e != nil {
			for _, old := range files {
				old.Close()
			}
			return nil, e
		}
		files = append(files, f)
	}
	return files, nil
}
func TestReleaseStoreCrashHelper(t *testing.T) {
	root := os.Getenv("XANDBOX_TEST_RELEASE_ROOT")
	if root == "" {
		return
	}
	raw, e := os.ReadFile(filepath.Join(root, "../input.json"))
	if e != nil {
		os.Exit(71)
	}
	m, e := Decode(raw)
	if e != nil {
		os.Exit(72)
	}
	dir, e := os.Open(root)
	if e != nil {
		os.Exit(73)
	}
	defer dir.Close()
	stage := os.Getenv("XANDBOX_TEST_RELEASE_STAGE")
	s := &store{root: dir, hook: func(at string) error {
		if at == stage {
			os.Exit(77)
		}
		return nil
	}}
	if _, e = s.publish(context.Background(), m, 0, request(), crashInputs); e != nil {
		os.Exit(74)
	}
	os.Exit(75)
}
func TestAbruptProcessDeathFreshHandleRecovery(t *testing.T) {
	for _, stage := range []string{"intent-written", "intent-renamed", "artifact-written-daemon", "artifact-sealed-workspace", "bundle-renamed", "reference-written", "reference-renamed", "intent-removed"} {
		t.Run(stage, func(t *testing.T) {
			s, m, _ := fixture(t)
			input := filepath.Join(filepath.Dir(s.root.Name()), "input.json")
			// The input is outside the store so strict store inventory is unchanged.
			// t.TempDir roots share a parent; each test owns its separate test directory.
			if e := os.WriteFile(input, encoded(m), 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReleaseStoreCrashHelper$")
			cmd.Env = []string{"GOMAXPROCS=2", "XANDBOX_TEST_RELEASE_ROOT=" + s.root.Name(), "XANDBOX_TEST_RELEASE_STAGE=" + stage}
			output, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 || len(output) != 0 {
				t.Fatalf("crash boundary not reached: %v (output bytes %d)", e, len(output))
			}
			dir, e := os.Open(s.root.Name())
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			recovered := &store{root: dir}
			value, e := recovered.publish(context.Background(), m, 0, request(), crashInputs)
			if e != nil || value.Revision != 1 || !value.PublicationDurable {
				t.Fatal("fresh process did not reconcile", value, e)
			}
			observed, e := recovered.status(context.Background())
			if e != nil || observed != value {
				t.Fatal(observed, e)
			}
		})
	}
}
