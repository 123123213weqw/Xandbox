// Package privatefile reads operator-owned private configuration without logging its contents.
package privatefile

import (
	"errors"
	"io"
	"os"
)

func Read(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || !ownedByCaller(before) {
		return nil, errors.New("private file must be caller-owned, regular, non-symlink and have no group/other permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 || !ownedByCaller(after) {
		return nil, errors.New("private file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("private file size limit exceeded")
	}
	return data, nil
}
