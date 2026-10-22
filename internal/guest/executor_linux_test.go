//go:build linux

package guest

import (
	"context"
	"testing"
)

func TestRealExecutorHasNoHostFallback(t *testing.T) {
	e := &Executor{}
	if _, err := e.Run(context.Background(), request()); err == nil {
		t.Fatal("unguarded executor executed")
	}
	if err := RunChild([]string{"/bin/sh", "-c", "exit 0"}); err == nil {
		t.Fatal("host child helper was not rejected")
	}
}

func TestCaptureBound(t *testing.T) {
	c := &capture{limit: 5}
	a, b := streamWriter{capture: c}, streamWriter{capture: c, stderr: true}
	if n, err := a.Write([]byte("abcd")); err != nil || n != 4 {
		t.Fatal(n, err)
	}
	if n, err := b.Write([]byte("efgh")); err != nil || n != 4 {
		t.Fatal(n, err)
	}
	out := c.output()
	if out.Stdout != "abcd" || out.Stderr != "e" || !out.Truncated {
		t.Fatalf("capture bound: %+v", out)
	}
}
