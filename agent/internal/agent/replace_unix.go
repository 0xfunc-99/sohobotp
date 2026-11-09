//go:build !windows

package agent

import "os"

// replaceBinary writes the new binary next to the running one and renames it over it
// (atomic; the running process keeps the old file until it exits).
func replaceBinary(exe string, data []byte) error {
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, exe)
}

func cleanupOldBinary() {}
