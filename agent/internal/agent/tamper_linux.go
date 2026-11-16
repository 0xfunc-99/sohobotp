//go:build linux

package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"multiotp-portal/agent/internal/state"
)

// bootTime is when Linux started (Unix time), 0 when unknown.
func bootTime() int64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	up, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return time.Now().Unix() - int64(up)
}

// serviceRunning: systemd says so, or the process that wrote the "running" note is alive
// (an agent started without systemd, in a container).
func serviceRunning() bool {
	if exec.Command("systemctl", "is-active", "--quiet", "sohobotp-agent").Run() == nil {
		return true
	}
	st, err := state.Load()
	if err != nil || st.Running == nil || st.Running.PID <= 0 || st.Running.PID == os.Getpid() {
		return false
	}
	return syscall.Kill(st.Running.PID, 0) == nil
}

func startService() {}

// systemStopping: systemd is shutting the machine down (a SIGTERM then is not a person).
func systemStopping() bool {
	out, _ := exec.Command("systemctl", "is-system-running").Output()
	return strings.TrimSpace(string(out)) == "stopping"
}

// stoppedByHand tells, when the service gets SIGTERM, whether someone stopped it while the
// machine keeps running. Without systemd nobody can tell: not reported.
func stoppedByHand() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return !systemStopping()
}

// Upgrade replaces the installed agent program with this one and restarts the service; the
// enrolment is kept. It returns the version that was installed.
func Upgrade() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if self == binaryPath {
		return "", errors.New("this is the installed agent: run the newer agent program instead")
	}
	old, err := installedVersion(binaryPath)
	if err != nil {
		return "", err
	}
	if err := copyFile(self, binaryPath, 0o755); err != nil {
		return old, fmt.Errorf("cannot replace %s: %w", binaryPath, err)
	}
	if out, err := exec.Command("systemctl", "restart", "sohobotp-agent").CombinedOutput(); err != nil {
		return old, fmt.Errorf("the program was replaced, but the service did not restart: %v: %s", err, out)
	}
	return old, nil
}
