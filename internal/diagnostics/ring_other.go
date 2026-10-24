//go:build !linux && !darwin

package diagnostics

import "errors"

func Start(string) (*Logger, error) {
	return nil, errors.New("diagnostic store requires supported Unix semantics")
}

func Read(string) (Snapshot, error) { return Snapshot{}, ErrWrite }
