//go:build !linux

package launch

import "errors"

func Run(path string) error { return errors.New("launcher requires Linux/systemd; no fallback") }

func FailureStage(err error) string { return "platform" }
