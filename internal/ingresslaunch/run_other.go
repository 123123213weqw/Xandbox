//go:build !linux

package ingresslaunch

import "errors"

func Run(string) error          { return errors.New("Linux systemd ingress service required") }
func FailureStage(error) string { return "platform" }
