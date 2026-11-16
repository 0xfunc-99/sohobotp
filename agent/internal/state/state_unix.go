//go:build !windows

package state

import "os"

func defaultDir() string { return "/etc/sohobotp-agent" }

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

func protectFile(path string) error { return os.Chmod(path, 0o600) }

func requestDir() string { return Dir() + "/requests" }

func ensureRequestDir(dir string) error { return ensureDir(dir) }
