//go:build !linux && !darwin

package firecracker

import (
	"context"
	"errors"
	"os"
)

func catalogLock(context.Context, string) (func(), error) {
	return nil, errors.New("snapshot catalog requires Unix filesystem locks")
}
func catalogOwned(os.FileInfo) bool { return false }
