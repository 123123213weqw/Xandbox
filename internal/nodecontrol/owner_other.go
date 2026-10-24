//go:build !linux && !darwin

package nodecontrol

import "os"

func privateSingleFile(os.FileInfo) bool { return false }
func privateSocket(os.FileInfo) bool     { return false }
