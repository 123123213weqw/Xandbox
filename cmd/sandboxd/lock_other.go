//go:build !linux && !darwin

package main

import "fmt"

func lockState(string) (func(), error) {
	return nil, fmt.Errorf("this prototype supports Linux and macOS only")
}
