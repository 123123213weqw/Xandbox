//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "gateway requires Linux privilege separation; no fallback")
	os.Exit(1)
}
