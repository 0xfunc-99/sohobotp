//go:build !linux && !windows

package agent

func bootTime() int64      { return 0 }
func serviceRunning() bool { return false }
func startService()        {}

// Upgrade is for Linux and Windows.
func Upgrade() (string, error) { return "", errUnsupported }
