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
	admins := "*S-1-5-32-544:(OI)(CI)F" // Administrators
	if locked {
		admins = "*S-1-5-32-544:(OI)(CI)RX" // tamper protection: read only
	}
	if applied[dir] == admins {
		return nil // already set by this process: icacls is slow, Save runs often
	}
	out, err := exec.Command("icacls", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", // SYSTEM
		"/grant:r", admins,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot restrict %s: %v: %s", dir, err, out)
	}
	applied[dir] = admins
	return nil
}

// applied remembers the permissions this process set on each folder.
var applied = map[string]string{}

func requestDir() string { return Dir() + "-requests" }

// ensureRequestDir: SYSTEM and Administrators, also under tamper protection (an administrator
// leaves the uninstall request there; the service checks the code itself).
func ensureRequestDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if applied[dir] != "" {
		return nil
	}
	out, err := exec.Command("icacls", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot restrict %s: %v: %s", dir, err, out)
	}
	applied[dir] = "requests"
	return nil
}

func protectFile(string) error { return nil } // inherits the folder ACL
