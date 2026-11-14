//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
)

// nativeArch is the processor of the machine, not of this program: an x64 agent running in
// the x64 emulation of Windows on ARM installs the ARM64 Sign-in (LogonUI loads only native
// DLLs).
func nativeArch() string {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err == nil {
		switch native {
		case 0xAA64:
			return "arm64"
		case 0x8664:
			return "amd64"
		case 0x014C:
			return "386"
		}
	}
	return runtime.GOARCH
}

// vcRuntimeInstalled: the Visual C++ 2015-2022 x64 runtime, looked up like Sign-in's installer
// does (its launch condition).
func vcRuntimeInstalled() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\Installer\Dependencies\Microsoft.VS.VC_RuntimeMinimumVSU_amd64,v14`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("Version")
	return err == nil && v != ""
}

// ensureSignin installs or updates SohobOTP Sign-in when the policy carries its installers.
// The result is a note for the log ("" when nothing was done).
func ensureSignin(p *protocol.WindowsPolicy) (string, error) {
	installed := inventory.SigninVersion()
	pkg, note, err := signinPlan(p, nativeArch(), installed)
	if err != nil || pkg == nil {
		return note, err
	}
	if packageSource == nil {
		return "", errors.New("cannot download installers (no portal connection)")
	}
	dir := filepath.Join(state.Dir(), "packages") // SYSTEM and Administrators only, like the agent state
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	var done []string
	if p.VCRedist != nil && !vcRuntimeInstalled() {
		if err := validPackage(p.VCRedist); err != nil {
			return "", fmt.Errorf("Visual C++ runtime: %w", err)
		}
		file, err := fetchInstaller(dir, "vc_redist.x64.exe", protocol.PackageRequest{Kind: "vcredist", Arch: "amd64", SHA256: p.VCRedist.SHA256}, p.VCRedist)
		if err != nil {
			return "", fmt.Errorf("Visual C++ runtime: %w", err)
		}
		// 0 installed, 1638 a newer version is installed, 3010 restart needed later
		if code, err := run(file, "/install", "/quiet", "/norestart"); err != nil || (code != 0 && code != 1638 && code != 3010) {
			return "", fmt.Errorf("Visual C++ runtime installer failed (exit %d): %v", code, err)
		}
		done = append(done, "Visual C++ runtime installed")
	}
	file, err := fetchInstaller(dir, "SohobOTPSignIn.msi", protocol.PackageRequest{Kind: "signin", Arch: nativeArch(), SHA256: pkg.SHA256}, pkg)
	if err != nil {
		return "", fmt.Errorf("SohobOTP Sign-in: %w", err)
	}
	logFile := filepath.Join(state.Dir(), "signin-install.log")
	// silent: the setup window is skipped; the settings are written by this agent right after
	code, err := run(filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe"), "/i", file, "/qn", "/norestart", "/l*v", logFile)
	if code == 1618 {
		return "", errors.New("SohobOTP Sign-in: another installation is running on this computer, trying again later")
	}
	if err != nil || (code != 0 && code != 3010 && code != 1641) {
		return "", fmt.Errorf("SohobOTP Sign-in installer failed (exit %d, log %s): %v", code, logFile, err)
	}
	if got := inventory.SigninVersion(); got == "" || versionLess(got, pkg.Version) || versionLess(pkg.Version, got) {
		return "", fmt.Errorf("SohobOTP Sign-in installer finished but version %q is installed, %s expected (log %s)", got, pkg.Version, logFile)
	}
	done = append(done, note)
	return strings.Join(done, "; "), nil
}

func fetchInstaller(dir, name string, req protocol.PackageRequest, pkg *protocol.Package) (string, error) {
	data, err := packageSource(req, pkg.Size+1)
	if err != nil {
		return "", fmt.Errorf("download from the portal failed: %w", err)
	}
	if err := verifyPackage(data, pkg); err != nil {
		return "", err
	}
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, data, 0o600); err != nil {
		return "", err
	}
	return file, nil
}

// run starts an installer and waits; the exit code is returned as is (installers use it).
func run(program string, args ...string) (int, error) {
	cmd := exec.Command(program, args...)
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}
