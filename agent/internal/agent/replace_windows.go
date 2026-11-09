//go:build windows

package agent

import "os"

// replaceBinary: a running .exe cannot be overwritten but can be renamed, so the current
// one becomes .old (removed at the next start) and the new one takes its place.
func replaceBinary(exe string, data []byte) error {
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		_ = os.Rename(old, exe)
		return err
	}
	return nil
}

func cleanupOldBinary() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}
