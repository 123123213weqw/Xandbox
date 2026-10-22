//go:build !linux && !darwin

package privatefile

import (
	"errors"
	"os"
)

func ownedByCaller(os.FileInfo) bool { return false }
func EnsureDirectory(string) (string, error) {
	return "", errors.New("private state directories require supported Unix ownership semantics")
}
