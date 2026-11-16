//go:build linux

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"multiotp-portal/agent/internal/bundle"
	"multiotp-portal/agent/internal/linuxapply"
	"multiotp-portal/agent/internal/protocol"
)

const (
	binaryPath = "/usr/local/sbin/sohobotp-agent"
	unitPath   = "/etc/systemd/system/sohobotp-agent.service"
)

// Unit is the systemd unit. It must be able to write /etc/pam.d, /etc/ssh and the RADIUS
// file, so ProtectSystem stays off; the rest is locked down.
const Unit = `[Unit]
Description=SohobOTP agent (two-factor policy for this machine)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/sohobotp-agent run
Restart=always
RestartSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
`

// RequireAdmin refuses to run without root.
func RequireAdmin() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run this command as root")
	}
	return nil
}

// InstallService copies the binary and starts the systemd service.
func InstallService() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if self != binaryPath {
		if err := copyFile(self, binaryPath, 0o755); err != nil {
			return fmt.Errorf("cannot install %s: %w", binaryPath, err)
		}
	}
	if err := os.WriteFile(unitPath, []byte(Unit), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "sohobotp-agent"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %v: %v: %s", args, err, out)
		}
	}
	return nil
}

// UninstallService removes the PAM changes, the service and the binary.
func UninstallService() error {
	if _, err := (&linuxapply.Applier{Sys: linuxapply.RealSystem{}}).Apply(&protocol.LinuxPolicy{Enabled: false}, ""); err != nil {
		return fmt.Errorf("could not remove the PAM changes: %w", err)
	}
	_ = exec.Command("systemctl", "disable", "--now", "sohobotp-agent").Run()
	_ = os.Remove(unitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = os.Remove(binaryPath)
	return nil
}

// RunService runs Serve until SIGTERM (systemd stops it).
func RunService() error {
	stop := make(chan struct{})
	go func() {
		waitForSignal()
		stopByHand.Store(stoppedByHand())
		close(stop)
	}()
	if Serve(stop) {
		os.Exit(3) // systemd (Restart=always) starts the updated binary
	}
	return nil
}

func copyFile(from, to string, mode os.FileMode) error {
	tmp := to + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	// without enrolment settings built into a downloaded agent (they hold the token)
	if err := bundle.CopyProgram(out, from); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, to)
}
