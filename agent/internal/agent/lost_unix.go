//go:build !windows

package agent

import (
	"errors"
	"os/exec"
	"strings"
)

// Linux sign-ins go through RADIUS (no offline copy): the portal's RADIUS refuses them.
func eraseSigninCache() (int, error) { return 0, nil }

// signOutSessions ends every login session of a user other than root (systemd-logind: SSH,
// console, graphical).
func signOutSessions() (int, error) {
	if _, err := exec.LookPath("loginctl"); err != nil {
		return 0, errors.New("loginctl not found (no systemd-logind): sessions not signed out")
	}
	raw, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		return 0, err
	}
	out := 0
	var failed error
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] == "0" { // SESSION UID USER ...; root keeps its sessions
			continue
		}
		if err := exec.Command("loginctl", "terminate-session", f[0]).Run(); err != nil {
			failed = errors.Join(failed, err)
			continue
		}
		out++
	}
	return out, failed
}
