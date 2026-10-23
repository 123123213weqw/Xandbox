//go:build linux || darwin

package nodecontrol

import (
	"os"
	"syscall"
)

func privateSingleFile(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && s.Nlink == 1 && info.Mode().IsRegular() && info.Mode().Perm() == 0600
}
func privateSocket(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && s.Nlink == 1 && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0600
}
