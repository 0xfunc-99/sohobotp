package agent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/release"
	"multiotp-portal/agent/internal/state"
)

// installedVersion asks the installed agent program for its version and checks that this
// program may replace it: only a newer one, and never on a machine with tamper protection
// (there the agent updates itself: computer policy, Agent version; or the MSI).
func installedVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "", fmt.Errorf("the installed agent (%s) does not answer: %w", path, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 || fields[0] != "sohobotp-agent" {
		return "", errors.New("the installed agent gave no version")
	}
	old := fields[1]
	if !release.Newer(inventory.Version, old) {
		return old, fmt.Errorf("the installed agent is version %s, this program is %s: nothing to upgrade", old, inventory.Version)
	}
	if st, err := state.Load(); err == nil && protectedNow(st, time.Now().Unix()) {
		return old, errors.New("this computer has tamper protection: its agent updates itself from the portal (computer policy, Agent version)")
	}
	return old, nil
}
