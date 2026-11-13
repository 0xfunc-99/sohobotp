//go:build linux

package inventory

import (
	"bufio"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"multiotp-portal/agent/internal/protocol"
)

var linuxName = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$`)

// noLogin are shells that cannot open a session: system accounts.
var noLogin = []string{"nologin", "false", "sync", "shutdown", "halt", "true"}

// accounts lists accounts that can sign in: root and every user from UID_MIN with a real shell.
func accounts() []protocol.Account {
	return parseAccounts(readFile("/etc/passwd"), readFile("/etc/group"), uidMin(readFile("/etc/login.defs")))
}

func readFile(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(raw)
}

func uidMin(loginDefs string) int {
	scanner := bufio.NewScanner(strings.NewReader(loginDefs))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "UID_MIN" {
			if n, err := strconv.Atoi(fields[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 1000
}

func parseAccounts(passwd, group string, minUID int) []protocol.Account {
	admins := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(group))
	for scanner.Scan() {
		f := strings.Split(scanner.Text(), ":")
		if len(f) == 4 && (f[0] == "sudo" || f[0] == "wheel" || f[0] == "admin") {
			for _, m := range strings.Split(f[3], ",") {
				admins[strings.TrimSpace(m)] = true
			}
		}
	}
	var out []protocol.Account
	scanner = bufio.NewScanner(strings.NewReader(passwd))
	for scanner.Scan() {
		f := strings.Split(scanner.Text(), ":")
		if len(f) != 7 || !linuxName.MatchString(f[0]) {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil || (uid != 0 && (uid < minUID || uid >= 60000)) {
			continue
		}
		shell := f[6]
		base := shell[strings.LastIndex(shell, "/")+1:]
		blocked := shell == ""
		for _, n := range noLogin {
			blocked = blocked || base == n
		}
		if blocked {
			continue
		}
		out = append(out, protocol.Account{Name: f[0], Kind: "local", Admin: uid == 0 || admins[f[0]]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > protocol.MaxAccounts {
		out = out[:protocol.MaxAccounts]
	}
	return out
}
