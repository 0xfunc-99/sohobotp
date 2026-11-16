//go:build !windows

package agent

// Linux has nothing to lock that root could not undo with one command: tamper protection is
// the uninstall code, the settings put back, and the events (tamper.go).

func lockMachine(bool) error { return nil }

func checkService() string { return "" }

func componentMissing() bool { return false }

// UninstallByInstaller is for the Windows MSI.
func UninstallByInstaller() (bool, error) { return false, nil }
