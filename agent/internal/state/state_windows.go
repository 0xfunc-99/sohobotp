//go:build windows

package state

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func defaultDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "SohobOTP", "agent")
}

// ensureDir creates the folder and replaces its ACL: SYSTEM and Administrators only,
// no inherited entries (so users cannot read the private keys).
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	out, err := exec.Command("icacls", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", // SYSTEM
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F", // Administrators
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot restrict %s: %v: %s", dir, err, out)
	}
	return nil
}

func protectFile(string) error { return nil } // inherits the folder ACL
