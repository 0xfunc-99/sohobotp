//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/state"
)

// Service permissions (SDDL). Locked: SYSTEM keeps everything (the service itself, Windows
// Installer and self-update run as SYSTEM); administrators may look at the service and start
// it, but not stop it, change it, delete it or change these permissions.
const (
	lockedSDDL  = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
	defaultSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
)

// lockedAsRead is the locked permissions as Windows gives them back (compared later).
var lockedAsRead string

func serviceSDDL() string {
	sd, err := windows.GetNamedSecurityInfo(serviceName, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ""
	}
	return sd.String()
}

func setServiceSDDL(sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(serviceName, windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		// the same with Windows' own tool (clearer errors in the log)
		if out, err2 := exec.Command("sc.exe", "sdset", serviceName, sddl).CombinedOutput(); err2 != nil {
			return fmt.Errorf("cannot set the service permissions: %v; sc sdset: %v %s", err, err2, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// lockMachine turns the Windows side of tamper protection on or off: service permissions,
// the program and state folders, and the Uninstall buttons. Every step is tried; the first
// error is returned.
func lockMachine(on bool) error {
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	icacls := func(args ...string) {
		if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
			keep(fmt.Errorf("icacls %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out))))
		}
	}
	if serviceExists() {
		if on {
			keep(setServiceSDDL(lockedSDDL))
			lockedAsRead = serviceSDDL()
		} else {
			lockedAsRead = ""
			keep(setServiceSDDL(defaultSDDL))
		}
	}
	if _, err := os.Stat(installDir()); err == nil {
		if on { // SYSTEM full; Administrators and Users read and run
			icacls(installDir(), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)RX", "/grant:r", "*S-1-5-32-545:(OI)(CI)RX")
		} else {
			icacls(installDir(), "/reset", "/T", "/C", "/Q")
		}
	}
	if _, err := os.Stat(state.Dir()); err == nil {
		owner := "*S-1-5-32-544" // Administrators
		if on {
			owner = "*S-1-5-18" // SYSTEM: an owner may always change permissions
		}
		icacls(state.Dir(), "/setowner", owner, "/T", "/C", "/Q")
		keep(state.EnsureDir()) // read-only for administrators when locked (state.SetLocked)
	}
	if on {
		keep(state.EnsureRequestDir())
	}
	hideUninstall(on)
	return first
}

// uninstallKeys returns the "Programs" entries of the agent and of SohobOTP Sign-in.
func uninstallKeys() []string {
	const root = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var found []string
	for _, n := range names {
		sub, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		display, _, _ := sub.GetStringValue("DisplayName")
		sub.Close()
		d := strings.ToLower(display)
		if d == "sohobotp agent" || strings.HasPrefix(d, "sohobotp sign-in") {
			found = append(found, root+`\`+n)
		}
	}
	return found
}

// agentProductCode is the Windows Installer product code of an agent installed with the MSI.
func agentProductCode() string {
	for _, path := range uninstallKeys() {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		display, _, _ := k.GetStringValue("DisplayName")
		msi, _, _ := k.GetIntegerValue("WindowsInstaller")
		k.Close()
		code := path[strings.LastIndex(path, `\`)+1:]
		if strings.EqualFold(display, "SohobOTP Agent") && msi == 1 && strings.HasPrefix(code, "{") {
			return code
		}
	}
	return ""
}

// hideUninstall hides (or shows again) the Uninstall and Change buttons of the agent and of
// SohobOTP Sign-in in Windows' list of programs. The values that were there are remembered in
// SohobOTPLock ("-" = absent) and put back.
func hideUninstall(on bool) {
	for _, path := range uninstallKeys() {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		prev, _, err := k.GetStringValue("SohobOTPLock")
		hidden := err == nil
		get := func(name string) string {
			if v, _, err := k.GetIntegerValue(name); err == nil {
				return strconv.FormatUint(v, 10)
			}
			return "-"
		}
		switch {
		case on && !hidden:
			_ = k.SetStringValue("SohobOTPLock", get("NoRemove")+","+get("NoModify"))
			_ = k.SetDWordValue("NoRemove", 1)
			_ = k.SetDWordValue("NoModify", 1)
		case on:
			_ = k.SetDWordValue("NoRemove", 1) // put back if someone changed them
			_ = k.SetDWordValue("NoModify", 1)
		case hidden:
			parts := strings.SplitN(prev, ",", 2)
			for i, name := range []string{"NoRemove", "NoModify"} {
				if i < len(parts) && parts[i] != "-" {
					n, _ := strconv.ParseUint(parts[i], 10, 32)
					_ = k.SetDWordValue(name, uint32(n))
				} else {
					_ = k.DeleteValue(name)
				}
			}
			_ = k.DeleteValue("SohobOTPLock")
		}
		k.Close()
	}
}

// checkService looks at the service of a protected machine: start type automatic, permissions
// as locked, Uninstall buttons hidden (SohobOTP Sign-in may have been installed again since).
// It puts back what differs and returns a note for the portal ("" when nothing had changed).
func checkService() string {
	hideUninstall(true)
	var notes []string
	if m, err := mgr.Connect(); err == nil {
		if s, err := m.OpenService(serviceName); err == nil {
			if c, err := s.Config(); err == nil && c.StartType != mgr.StartAutomatic {
				c.StartType = mgr.StartAutomatic
				if s.UpdateConfig(c) == nil {
					notes = append(notes, "the agent service was no longer started automatically (put back)")
				}
			}
			s.Close()
		}
		m.Disconnect()
	}
	if now := serviceSDDL(); lockedAsRead != "" && now != "" && now != lockedAsRead {
		if setServiceSDDL(lockedSDDL) == nil {
			notes = append(notes, "the permissions of the agent service had been changed (put back)")
		}
	}
	return strings.Join(notes, "; ")
}

func componentMissing() bool { return inventory.SigninVersion() == "" }

// bootTime is when Windows started (Unix time).
func bootTime() int64 { return time.Now().Add(-windows.DurationSinceBoot()).Unix() }

// openService opens the service with just the rights asked for: under tamper protection an
// administrator may query and start it, nothing more.
func openService(access uint32) (windows.Handle, func(), error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, nil, err
	}
	name, _ := windows.UTF16PtrFromString(serviceName)
	h, err := windows.OpenService(scm, name, access)
	if err != nil {
		windows.CloseServiceHandle(scm)
		return 0, nil, err
	}
	return h, func() { windows.CloseServiceHandle(h); windows.CloseServiceHandle(scm) }, nil
}

func serviceExists() bool {
	_, done, err := openService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST)
	}
	done()
	return true
}

func serviceRunning() bool {
	h, done, err := openService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer done()
	var status windows.SERVICE_STATUS
	return windows.QueryServiceStatus(h, &status) == nil && status.CurrentState == windows.SERVICE_RUNNING
}

func startService() {
	h, done, err := openService(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return
	}
	defer done()
	if windows.StartService(h, 0, nil) != nil {
		return
	}
	for i := 0; i < 20 && !serviceRunning(); i++ {
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(time.Second) // let it load its state before it is asked
}

// UninstallByInstaller removes an agent that was installed with the MSI the way Windows
// expects (Windows Installer), so it also leaves the list of programs. It returns false when
// the agent was not installed with the MSI. Windows Installer is started and not waited for:
// it cannot remove this program while it runs.
func UninstallByInstaller() (bool, error) {
	code := agentProductCode()
	if code == "" {
		return false, nil
	}
	cmd := exec.Command(os.Getenv("SystemRoot")+`\System32\msiexec.exe`, "/x", code, "/qn", "/norestart")
	if err := cmd.Start(); err != nil {
		return true, err
	}
	_ = cmd.Process.Release()
	return true, nil
}

// Upgrade replaces the installed agent program with this one and starts the service again;
// the enrolment is kept. It returns the version that was installed.
func Upgrade() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	target := installDir() + `\sohobotp-agent.exe`
	if sameFile(self, target) {
		return "", errors.New("this is the installed agent: run the newer agent program instead")
	}
	old, err := installedVersion(target)
	if err != nil {
		return "", err
	}
	m, err := mgr.Connect()
	if err != nil {
		return old, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return old, fmt.Errorf("cannot open the %s service: %w", serviceName, err)
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 60; i++ {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	fresh := target + ".new"
	if err := copyFile(self, fresh); err != nil {
		_ = s.Start()
		return old, err
	}
	_ = os.Remove(target + ".old")
	if err := os.Rename(target, target+".old"); err != nil {
		_ = os.Remove(fresh)
		_ = s.Start()
		return old, err
	}
	if err := os.Rename(fresh, target); err != nil {
		_ = os.Rename(target+".old", target)
		_ = s.Start()
		return old, err
	}
	return old, s.Start()
}
