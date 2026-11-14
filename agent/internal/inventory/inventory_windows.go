//go:build windows

package inventory

import (
	"strings"

	"golang.org/x/sys/windows/registry"

	"multiotp-portal/agent/internal/protocol"
)

func platform(inv *protocol.Inventory) {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		name, _, _ := k.GetStringValue("ProductName")
		display, _, _ := k.GetStringValue("DisplayVersion")
		build, _, _ := k.GetStringValue("CurrentBuild")
		k.Close()
		inv.OSName = name
		inv.OSVersion = strings.TrimSpace(display + " " + build)
		inv.Kernel = build
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE); err == nil {
		inv.Domain, _, _ = k.GetStringValue("Domain")
		k.Close()
	}
	inv.Component = protocol.Component{Name: "sohobotp-signin", Version: credentialProviderVersion()}
}

// SigninVersion is the installed SohobOTP Sign-in version ("" when not installed).
func SigninVersion() string { return credentialProviderVersion() }

// credentialProviderVersion reads the installed SohobOTP Sign-in version
// from the uninstall entries (64-bit view).
func credentialProviderVersion() string {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return ""
	}
	defer root.Close()
	names, _ := root.ReadSubKeyNames(-1)
	for _, n := range names {
		k, err := registry.OpenKey(root, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		display, _, _ := k.GetStringValue("DisplayName")
		version, _, _ := k.GetStringValue("DisplayVersion")
		k.Close()
		if strings.HasPrefix(strings.ToLower(display), "sohobotp sign-in") {
			return version
		}
	}
	return ""
}
