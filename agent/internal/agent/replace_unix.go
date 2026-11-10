//go:build !windows

package agent

// cleanupOldBinary: nothing to clean on Linux (see safeupdate.go for the .previous binary).
func cleanupOldBinary() {}
