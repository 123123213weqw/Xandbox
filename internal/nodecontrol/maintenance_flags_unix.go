//go:build linux || darwin

package nodecontrol

import "syscall"

const maintenanceNoFollow = syscall.O_NOFOLLOW
