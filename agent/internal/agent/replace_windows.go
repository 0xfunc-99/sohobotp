//go:build windows

package agent

import "os"

// cleanupOldBinary removes the .old file left by agents up to 0.1 (they renamed the running
// binary to .old during a self-update; now see safeupdate.go).
func cleanupOldBinary() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}
