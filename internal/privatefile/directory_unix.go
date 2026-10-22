//go:build linux || darwin

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func ownedByCaller(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

// EnsureDirectory creates private components only below already-validated
// ancestors. Mkdir (not MkdirAll) never follows a raced-in symlink on EEXIST.
// Other UIDs cannot replace a trusted child below an allowed sticky directory.
// Root never traverses symlinks. Non-root may traverse root-owned OS aliases
// (e.g. macOS /var), after validating their complete target ancestry as well.
func EnsureDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if abs == "/" {
		return "", errors.New("private state cannot be the filesystem root")
	}
	if err := walkDirectory(abs, true, true, 0); err != nil {
		return "", err
	}
	return abs, nil
}

func walkDirectory(path string, create, privateLeaf bool, depth int) error {
	if depth > 40 {
		return errors.New("directory symlink depth exceeded")
	}
	root, err := os.Lstat("/")
	if err != nil {
		return err
	}
	rootStat, ok := root.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 || !root.IsDir() || root.Mode().Perm()&0022 != 0 {
		return errors.New("untrusted filesystem root")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	prefix := "/"
	for n, part := range parts {
		if part == "" {
			continue
		}
		prefix = filepath.Join(prefix, part)
		info, err := os.Lstat(prefix)
		if os.IsNotExist(err) && create {
			if e := os.Mkdir(prefix, 0700); e != nil && !os.IsExist(e) {
				return e
			}
			info, err = os.Lstat(prefix)
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return errors.New("untrusted directory owner")
		}
		leaf := privateLeaf && n == len(parts)-1
		if info.Mode()&os.ModeSymlink != 0 {
			if leaf || os.Geteuid() == 0 || stat.Uid != 0 {
				return errors.New("untrusted directory symlink")
			}
			target, err := os.Readlink(prefix)
			if err != nil {
				return err
			}
			for _, p := range strings.Split(target, "/") {
				if p == ".." {
					return errors.New("parent-traversing directory symlink")
				}
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(prefix), target)
			}
			if err := walkDirectory(filepath.Clean(target), false, false, depth+1); err != nil {
				return err
			}
			continue
		}
		if !info.IsDir() {
			return errors.New("state path component is not a directory")
		}
		if leaf {
			if !ownedByCaller(info) || info.Mode().Perm()&0077 != 0 {
				return errors.New("state directory must be caller-owned and private")
			}
		} else if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return errors.New("untrusted writable directory ancestor")
		}
	}
	return nil
}
