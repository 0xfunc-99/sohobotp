//go:build linux

package inventory

import (
	"bufio"
	"os"
	"os/exec"
	"strings"

	"multiotp-portal/agent/internal/protocol"
)

func platform(inv *protocol.Inventory) {
	if f, err := os.Open("/etc/os-release"); err == nil {
		defer f.Close()
		values := map[string]string{}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if k, v, ok := strings.Cut(scanner.Text(), "="); ok {
				values[k] = strings.Trim(v, `"'`)
			}
		}
		inv.OSName = values["NAME"]
		inv.OSVersion = values["VERSION_ID"]
	}
	if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		inv.Kernel = strings.TrimSpace(string(raw))
	}
	if out, err := exec.Command("hostname", "-d").Output(); err == nil {
		inv.Domain = strings.TrimSpace(string(out))
	}
	inv.Component = protocol.Component{Name: "pam_radius", Version: pamRadiusVersion()}
}

func pamRadiusVersion() string {
	if out, err := exec.Command("dpkg-query", "-W", "-f=${Version}", "libpam-radius-auth").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("rpm", "-q", "--qf", "%{VERSION}", "pam_radius").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}
