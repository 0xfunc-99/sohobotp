//go:build !linux && !windows

package agent

import (
	"errors"

	"multiotp-portal/agent/internal/protocol"
)

type unsupported struct{}

// NewApplier: development builds (macOS) cannot apply policies.
func NewApplier() Applier { return unsupported{} }

func (unsupported) Apply(*protocol.Config) (string, error) {
	return "", errors.New("this operating system is not supported by the SohobOTP agent")
}

// DryRun is Linux-only.
func DryRun(protocol.LinuxPolicy, string) (string, error) {
	return "", errors.New("apply --dry-run is available on Linux only")
}
