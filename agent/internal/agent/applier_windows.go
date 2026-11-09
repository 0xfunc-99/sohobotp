//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
	"multiotp-portal/agent/internal/winapply"
)

type windowsApplier struct{}

// NewApplier returns the Credential Provider applier.
func NewApplier() Applier { return windowsApplier{} }

func (windowsApplier) Apply(cfg *protocol.Config) (string, error) {
	var p protocol.WindowsPolicy
	if err := json.Unmarshal(cfg.Policy, &p); err != nil {
		return "", fmt.Errorf("Windows policy not readable: %w", err)
	}
	changed, err := winapply.Apply(winapply.RealRegistry{}, &p, cfg.Secrets["cp_shared_secret"], false)
	if err != nil {
		return "", err
	}
	if len(changed) == 0 {
		return "nothing to change", nil
	}
	return "Credential Provider values set: " + strings.Join(changed, ", "), nil
}

// DryRun is Linux-only.
func DryRun(protocol.LinuxPolicy, string) (string, error) {
	return "", fmt.Errorf("apply --dry-run is available on Linux only")
}

// OpenLogFile sends the log to agent.log in the state folder (services have no console).
func OpenLogFile() {
	f, err := os.OpenFile(filepath.Join(state.Dir(), "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		logFile = f
	}
}
