//go:build !linux && !darwin

package nodecontrol

// Existing privatefile/owner checks refuse unsupported store platforms; no
// alternate unpinned maintenance client/transport is introduced here.
const maintenanceNoFollow = 0
