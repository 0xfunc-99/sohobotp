//go:build !windows

package agent

// Linux machines are enrolled with "install" (or configuration management running it).
func readBootstrap() (Enrolment, error) { return Enrolment{}, ErrNoBootstrap }

func clearBootstrapToken() {}
