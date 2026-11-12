//go:build !windows

package agent

import "errors"

// Linux machines are enrolled with "install" (or configuration management running it).
func readBootstrap() (Enrolment, error) { return Enrolment{}, ErrNoBootstrap }

func clearBootstrapToken() {}

// SaveBootstrapToken is used by the Windows MSI only.
func SaveBootstrapToken(string) error {
	return errors.New("save-token is used by the Windows installer only")
}

// PauseIfOwnConsole and RelaunchElevated matter on Windows only (a double-clicked agent).
func PauseIfOwnConsole() {}

func RelaunchElevated() bool { return false }
