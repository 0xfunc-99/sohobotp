//go:build windows

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"multiotp-portal/agent/internal/bundle"
)

const serviceName = "SohobOTPAgent"

func installDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "SohobOTP", "Agent")
}

// RequireAdmin refuses to run without an elevated administrator token.
func RequireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("run this command from an administrator (elevated) prompt")
	}
	return nil
}

// InstallService copies the executable to Program Files and registers an automatic
// service that restarts on failure.
func InstallService() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	target := filepath.Join(installDir(), "sohobotp-agent.exe")
	if !sameFile(self, target) {
		if err := os.MkdirAll(installDir(), 0o755); err != nil {
			return err
		}
		if err := copyFile(self, target); err != nil {
			return err
		}
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if serviceExists() {
		return fmt.Errorf("the %s service already exists", serviceName)
	}
	s, err := m.CreateService(serviceName, target, mgr.Config{
		DisplayName: "SohobOTP Agent",
		Description: "Applies the SohobOTP two-factor policy (SohobOTP Sign-in) of this machine.",
		StartType:   mgr.StartAutomatic,
	}, "run")
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}}, 86400)
	return s.Start()
}

// UninstallService stops and removes the service and the installed executable. The
// Credential Provider itself is uninstalled with its own MSI.
func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		_, _ = s.Control(svc.Stop)
		time.Sleep(2 * time.Second)
		_ = s.Delete()
		s.Close()
	}
	_ = os.Remove(filepath.Join(installDir(), "sohobotp-agent.exe"))
	return nil
}

// RunService runs under the Service Control Manager, or in the console when started by hand.
func RunService() error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		_ = Serve(make(chan struct{}))
		return nil
	}
	OpenLogFile()
	ensureRecovery()
	return svc.Run(serviceName, &handler{})
}

type handler struct{}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan struct{})
	restart := false
	go func() {
		restart = Serve(stop)
		close(done)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case <-done:
			if restart {
				// a non-zero exit is a failure: the recovery action starts the updated binary
				return false, 1
			}
			return false, 0
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				stopByHand.Store(req.Cmd == svc.Stop) // not at shutdown (tamper.go)
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done
				return false, 0
			}
		}
	}
}

// ensureRecovery makes the service restart after a failure, also when it was installed by
// the MSI (wixl cannot write the failure-actions table).
func ensureRecovery() {
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}}, 86400)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
}

func sameFile(a, b string) bool {
	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(sa, sb)
}

func copyFile(from, to string) error {
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	// without enrolment settings built into a downloaded agent (they hold the token)
	if err := bundle.CopyProgram(out, from); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
