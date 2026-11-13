// Package linuxapply applies a SohobOTP Linux policy: PAM asks for the code through
// pam_radius_auth after the normal password.
//
// Safety rules (lock-out protection):
//   - the agent only ADDS two lines (a marker and "auth include sohobotp-2fa") right after
//     the existing password step of a service; it never removes or reorders other lines;
//   - excluded users (root always) and groups skip only the code line, never the password;
//   - every change is snapshotted first and rolled back if any step or validation fails;
//   - disabling removes exactly what was added, so the files are restored byte for byte.
package linuxapply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"multiotp-portal/agent/internal/protocol"
)

const (
	moduleName    = "sohobotp-2fa"
	marker        = "# SohobOTP two-factor (managed by sohobotp-agent, do not edit)"
	includeLine   = "auth include " + moduleName
	managedHeader = "# Managed by the SohobOTP agent - do not edit, changes are overwritten."
	// sshd keeps the FIRST value it reads: the drop-in must sort before the distribution's own
	// (RHEL's 50-redhat.conf sets ChallengeResponseAuthentication no).
	sshDropIn       = "/etc/ssh/sshd_config.d/00-sohobotp.conf"
	legacySSHDropIn = "/etc/ssh/sshd_config.d/50-sohobotp.conf"
)

// Services the agent may protect, in a fixed order.
var Services = []string{"sshd", "sudo", "login", "su"}

var (
	nameRe     = regexp.MustCompile(`(?i)^[a-z_][a-z0-9_.-]{0,31}\$?$`)
	hostRe     = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)
	secretRe   = regexp.MustCompile(`^[\x21-\x7e]{8,128}$`)
	passwordRe = regexp.MustCompile(`^\s*(@include\s+common-auth\b|auth\s+(include|substack)\s+(common-auth|password-auth|system-auth|system-login)\b)`)
	includeRe  = regexp.MustCompile(`(?mi)^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$`)
	// "auth include system-auth": a "sufficient" success inside system-auth would end the
	// whole stack before the code is asked (RHEL); it becomes a substack, which isolates it.
	authIncludeRe = regexp.MustCompile(`^(\s*auth\s+)include(\s+(?:common-auth|password-auth|system-auth|system-login)\b.*)$`)
	replacedRe    = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(marker) + ` - replaced: (.*)\n.*\n` + regexp.QuoteMeta(includeLine) + `\n`)
)

// System runs commands; replaced in tests.
type System interface {
	Run(name string, args ...string) (string, error)
	Exists(name string) bool // command available in PATH
}

// Applier applies policies under Root ("" = the real "/").
type Applier struct {
	Root   string
	Sys    System
	DryRun bool
}

// Change is one file the policy creates, modifies or removes.
type Change struct {
	Path    string // absolute path on the machine (without Root)
	Content *string
	Mode    os.FileMode
}

func (a *Applier) p(path string) string { return filepath.Join(a.Root, path) }

// RadiusFile is the pam_radius server file of this distribution: /etc/raddb/server (older
// RHEL), /etc/pam_radius.conf (RHEL/Rocky 9, EPEL pam_radius 2.x) or /etc/pam_radius_auth.conf
// (Debian/Ubuntu). The module line always names it with conf=.
func (a *Applier) RadiusFile() string {
	for _, f := range []string{"/etc/raddb/server", "/etc/pam_radius.conf", "/etc/pam_radius_auth.conf"} {
		if _, err := os.Stat(a.p(f)); err == nil {
			return f
		}
	}
	if _, err := os.Stat(a.p("/etc/redhat-release")); err == nil {
		return "/etc/pam_radius.conf"
	}
	return "/etc/pam_radius_auth.conf"
}

// Validate refuses anything the portal should never send (defence in depth).
func Validate(p *protocol.LinuxPolicy, secret string) error {
	if !p.Enabled {
		return nil
	}
	if len(p.RadiusServers) == 0 || len(p.RadiusServers) > 8 {
		return errors.New("policy needs 1 to 8 RADIUS servers")
	}
	for _, s := range p.RadiusServers {
		if !hostRe.MatchString(s.Host) || s.Port < 1 || s.Port > 65535 {
			return fmt.Errorf("invalid RADIUS server %q", s.Host)
		}
	}
	if p.Timeout < 1 || p.Timeout > 60 {
		return errors.New("RADIUS timeout must be 1-60 seconds")
	}
	if !secretRe.MatchString(secret) {
		return errors.New("RADIUS secret missing or not printable ASCII without spaces")
	}
	if len(p.Services) == 0 {
		return errors.New("policy protects no service")
	}
	known := map[string]bool{}
	for _, s := range Services {
		known[s] = true
	}
	for _, s := range p.Services {
		if !known[s] {
			return fmt.Errorf("unknown PAM service %q", s)
		}
	}
	for _, n := range append(append([]string{}, p.ExcludedUsers...), p.ExcludedGroups...) {
		if !nameRe.MatchString(n) {
			return fmt.Errorf("invalid user or group name %q", n)
		}
	}
	for svc, users := range p.ExcludedUsersByService {
		if !known[svc] {
			return fmt.Errorf("unknown PAM service %q", svc)
		}
		if len(users) > protocol.MaxAccounts {
			return fmt.Errorf("too many users without a code for %s", svc)
		}
		for _, u := range users {
			if !nameRe.MatchString(u) {
				return fmt.Errorf("invalid user name %q", u)
			}
		}
	}
	return nil
}

// ModuleFile is the content of /etc/pam.d/sohobotp-2fa.
func ModuleFile(p *protocol.LinuxPolicy, radiusFile string) string {
	users := []string{"root"}
	for _, u := range p.ExcludedUsers {
		if u != "root" {
			users = append(users, u)
		}
	}
	var skip []string
	skip = append(skip, "user in "+strings.Join(users, ":"))
	for _, g := range p.ExcludedGroups {
		skip = append(skip, "user ingroup "+g)
	}
	// users who skip the code only for some services (pam_succeed_if: all conditions must hold)
	for _, svc := range Services {
		if users := p.ExcludedUsersByService[svc]; len(users) > 0 {
			skip = append(skip, "user in "+strings.Join(users, ":")+" service in "+svc)
		}
	}
	var b strings.Builder
	b.WriteString(managedHeader + "\n")
	b.WriteString("# Asks for the SohobOTP code after the normal password. Excluded users and groups\n")
	b.WriteString("# skip only the code line: they still need their normal password.\n")
	for i, cond := range skip {
		// jump over the remaining exclusion lines and the pam_radius line, to the end of this file
		fmt.Fprintf(&b, "auth [success=%d default=ignore] pam_succeed_if.so quiet %s\n", len(skip)-i, cond)
	}
	// force_prompt: always ask for the code; without it pam_radius re-sends the password
	// typed for the previous module (seen with libpam-radius-auth 2.0.0).
	fmt.Fprintf(&b, "auth required pam_radius_auth.so conf=%s prompt=code force_prompt\n", radiusFile)
	return b.String()
}

// RadiusConf is the content of the pam_radius server file (root 0600).
func RadiusConf(p *protocol.LinuxPolicy, secret string) string {
	var b strings.Builder
	b.WriteString(managedHeader + "\n# server[:port]\tshared_secret\ttimeout\n")
	for _, s := range p.RadiusServers {
		host := s.Host
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		fmt.Fprintf(&b, "%s:%d\t%s\t%d\n", host, s.Port, secret, p.Timeout)
	}
	return b.String()
}

// SSHDropIn is the sshd drop-in: passwords go through PAM keyboard-interactive, so the
// code is always asked; optionally SSH keys need the code too.
func SSHDropIn(p *protocol.LinuxPolicy) string {
	var b strings.Builder
	b.WriteString(managedHeader + "\nUsePAM yes\nKbdInteractiveAuthentication yes\nPasswordAuthentication no\n")
	if p.SSHKeysNeedCode {
		b.WriteString("AuthenticationMethods publickey,keyboard-interactive keyboard-interactive\n")
	}
	return b.String()
}

// WithInclude adds the marker and include lines after the password step (idempotent).
func WithInclude(service, content string) (string, error) {
	if strings.Contains(content, "\n"+includeLine+"\n") {
		return content, nil
	}
	lines := strings.SplitAfter(content, "\n")
	for i, line := range lines {
		if passwordRe.MatchString(line) {
			bare := strings.TrimSuffix(line, "\n")
			if m := authIncludeRe.FindStringSubmatch(bare); m != nil {
				// keep the original line in the marker so disabling restores it exactly
				out := strings.Join(lines[:i], "") + marker + " - replaced: " + bare + "\n" + m[1] + "substack" + m[2] + "\n" + includeLine + "\n" + strings.Join(lines[i+1:], "")
				return out, nil
			}
			out := strings.Join(lines[:i], "") + bare + "\n" + marker + "\n" + includeLine + "\n" + strings.Join(lines[i+1:], "")
			return out, nil
		}
	}
	return "", fmt.Errorf("cannot find the password step in /etc/pam.d/%s (no common-auth / system-auth / password-auth include): not changed", service)
}

// WithoutInclude removes exactly what WithInclude added (and restores a replaced line).
func WithoutInclude(content string) string {
	if m := replacedRe.FindStringSubmatchIndex(content); m != nil {
		return content[:m[0]] + content[m[2]:m[3]] + "\n" + content[m[1]:]
	}
	return strings.Replace(content, marker+"\n"+includeLine+"\n", "", 1)
}

// Plan computes the file changes for a policy without touching anything.
func (a *Applier) Plan(p *protocol.LinuxPolicy, secret string) ([]Change, error) {
	if err := Validate(p, secret); err != nil {
		return nil, err
	}
	var changes []Change
	str := func(s string) *string { return &s }
	radiusFile := a.RadiusFile()
	wanted := map[string]bool{}
	if p.Enabled {
		for _, s := range p.Services {
			wanted[s] = true
		}
	}
	for _, svc := range Services {
		path := "/etc/pam.d/" + svc
		raw, err := os.ReadFile(a.p(path))
		if errors.Is(err, os.ErrNotExist) {
			if wanted[svc] && svc == "sshd" {
				return nil, errors.New("SSH is protected by the policy but /etc/pam.d/sshd does not exist (is openssh-server installed?)")
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		next := WithoutInclude(string(raw))
		if wanted[svc] {
			if next, err = WithInclude(svc, next); err != nil {
				return nil, err
			}
		}
		if next != string(raw) {
			changes = append(changes, Change{Path: path, Content: str(next)})
		}
	}
	backup := radiusFile + ".sohobotp-orig"
	current, currentErr := os.ReadFile(a.p(radiusFile))
	ours := currentErr == nil && strings.HasPrefix(string(current), managedHeader)
	if p.Enabled {
		changes = append(changes,
			Change{Path: "/etc/pam.d/" + moduleName, Content: str(ModuleFile(p, radiusFile)), Mode: 0o644},
			Change{Path: radiusFile, Content: str(RadiusConf(p, secret)), Mode: 0o600},
		)
		if currentErr == nil && !ours {
			// keep the file the package (or an administrator) put there, restored when 2FA is turned off
			changes = append(changes, Change{Path: backup, Content: str(string(current)), Mode: 0o600})
		}
	} else {
		changes = append(changes, Change{Path: "/etc/pam.d/" + moduleName})
		if original, err := os.ReadFile(a.p(backup)); err == nil {
			changes = append(changes, Change{Path: radiusFile, Content: str(string(original)), Mode: 0o600}, Change{Path: backup})
		} else if ours {
			changes = append(changes, Change{Path: radiusFile})
		}
	}
	changes = append(changes, Change{Path: legacySSHDropIn}) // name used by the first test builds
	if wanted["sshd"] {
		cfg, err := os.ReadFile(a.p("/etc/ssh/sshd_config"))
		if err != nil {
			return nil, fmt.Errorf("cannot read /etc/ssh/sshd_config: %w", err)
		}
		if !includeRe.Match(cfg) {
			return nil, errors.New("/etc/ssh/sshd_config does not include /etc/ssh/sshd_config.d/*.conf: add that Include line first")
		}
		changes = append(changes, Change{Path: sshDropIn, Content: str(SSHDropIn(p)), Mode: 0o644})
	} else {
		changes = append(changes, Change{Path: sshDropIn})
	}
	return a.dropUnchanged(changes), nil
}

func (a *Applier) dropUnchanged(changes []Change) []Change {
	var out []Change
	for _, c := range changes {
		raw, err := os.ReadFile(a.p(c.Path))
		exists := err == nil
		if c.Content == nil && !exists {
			continue
		}
		if c.Content != nil && exists && string(raw) == *c.Content {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

type snapshot struct {
	path    string
	content []byte
	mode    os.FileMode
	existed bool
}

// Apply writes the plan, validates, reloads sshd, or restores every file on failure.
func (a *Applier) Apply(p *protocol.LinuxPolicy, secret string) ([]Change, error) {
	changes, err := a.Plan(p, secret)
	if err != nil {
		return nil, err
	}
	if a.DryRun || len(changes) == 0 {
		return changes, nil
	}
	if p.Enabled {
		if err := a.ensureModule(); err != nil {
			return nil, err
		}
		if err := a.ensureSELinux(); err != nil {
			return nil, err
		}
	}
	var snaps []snapshot
	for _, c := range changes {
		s := snapshot{path: c.Path}
		if st, err := os.Stat(a.p(c.Path)); err == nil {
			s.existed, s.mode = true, st.Mode().Perm()
			if s.content, err = os.ReadFile(a.p(c.Path)); err != nil {
				return nil, err
			}
		}
		snaps = append(snaps, s)
	}
	rollback := func(cause error) error {
		for _, s := range snaps {
			if s.existed {
				_ = writeAtomic(a.p(s.path), s.content, s.mode)
			} else {
				_ = os.Remove(a.p(s.path))
			}
		}
		return fmt.Errorf("%w (previous configuration restored)", cause)
	}
	sshChanged := false
	for i, c := range changes {
		if c.Path == sshDropIn || c.Path == legacySSHDropIn {
			sshChanged = true
		}
		if c.Content == nil {
			if err := os.Remove(a.p(c.Path)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, rollback(err)
			}
			continue
		}
		mode := c.Mode
		if snaps[i].existed {
			mode = snaps[i].mode // keep the mode of files the agent does not own
			if c.Mode != 0 {
				mode = c.Mode
			}
		}
		if mode == 0 {
			mode = 0o644
		}
		if err := os.MkdirAll(filepath.Dir(a.p(c.Path)), 0o755); err != nil {
			return nil, rollback(err)
		}
		if err := writeAtomic(a.p(c.Path), []byte(*c.Content), mode); err != nil {
			return nil, rollback(err)
		}
	}
	if sshChanged && a.Sys.Exists("sshd") {
		if out, err := a.Sys.Run("sshd", "-t"); err != nil {
			return nil, rollback(fmt.Errorf("sshd -t refused the configuration: %s", firstLine(out)))
		}
		a.reloadSSH()
	}
	return changes, nil
}

func (a *Applier) ensureModule() error {
	for _, dir := range []string{"/lib/x86_64-linux-gnu/security", "/lib/aarch64-linux-gnu/security", "/usr/lib/x86_64-linux-gnu/security", "/usr/lib/aarch64-linux-gnu/security", "/lib64/security", "/usr/lib64/security", "/lib/security", "/usr/lib/security"} {
		if _, err := os.Stat(a.p(dir + "/pam_radius_auth.so")); err == nil {
			return nil
		}
	}
	if a.Root != "" {
		return errors.New("pam_radius_auth.so is not installed")
	}
	var out string
	var err error
	switch {
	case a.Sys.Exists("apt-get"):
		// a fresh machine may have no package lists yet, and unattended upgrades may hold the
		// lock for a while after the first boot: wait for it instead of failing at once
		lock := "DPkg::Lock::Timeout=300"
		_, _ = a.Sys.Run("apt-get", "-o", lock, "update")
		out, err = a.Sys.Run("apt-get", "-o", lock, "install", "-y", "libpam-radius-auth")
	case a.Sys.Exists("dnf"):
		out, err = a.Sys.Run("dnf", "install", "-y", "pam_radius")
		if err != nil { // pam_radius is in EPEL (Rocky/Alma: epel-release; RHEL: enable EPEL)
			_, _ = a.Sys.Run("dnf", "install", "-y", "epel-release")
			out, err = a.Sys.Run("dnf", "install", "-y", "pam_radius")
		}
	default:
		return errors.New("pam_radius_auth.so is not installed and no apt-get or dnf to install it")
	}
	if err != nil {
		return fmt.Errorf("installing pam_radius failed (install it by hand: Debian/Ubuntu libpam-radius-auth, RHEL/Rocky pam_radius from EPEL): %s", firstLine(out))
	}
	return nil
}

// ensureSELinux: with SELinux enforcing (RHEL/Rocky default), sshd and sudo may only reach a
// RADIUS server when the boolean authlogin_radius is on; it is off by default. Left on when
// 2FA is turned off again (it only allows the connection).
func (a *Applier) ensureSELinux() error {
	if !a.Sys.Exists("getsebool") || !a.Sys.Exists("setsebool") {
		return nil
	}
	if _, err := a.Sys.Run("selinuxenabled"); err != nil {
		return nil // SELinux disabled (or selinuxenabled missing)
	}
	out, err := a.Sys.Run("getsebool", "authlogin_radius")
	if err == nil && strings.Contains(out, "--> on") {
		return nil
	}
	if out, err := a.Sys.Run("setsebool", "-P", "authlogin_radius", "on"); err != nil {
		return fmt.Errorf("SELinux: cannot turn on authlogin_radius (setsebool -P authlogin_radius on): %s", firstLine(out))
	}
	return nil
}

func (a *Applier) reloadSSH() {
	if a.Sys.Exists("systemctl") {
		if _, err := a.Sys.Run("systemctl", "is-active", "--quiet", "ssh"); err == nil {
			_, _ = a.Sys.Run("systemctl", "reload", "ssh")
			return
		}
		if _, err := a.Sys.Run("systemctl", "is-active", "--quiet", "sshd"); err == nil {
			_, _ = a.Sys.Run("systemctl", "reload", "sshd")
			return
		}
	}
	// no systemd (containers): signal the listening sshd
	if raw, err := os.ReadFile(a.p("/run/sshd.pid")); err == nil {
		// only if that process really is sshd (a stale pid file must not signal anything else;
		// in containers sshd may be process 1)
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 0 {
			if comm, err := os.ReadFile(a.p(fmt.Sprintf("/proc/%d/comm", pid))); err == nil && strings.TrimSpace(string(comm)) == "sshd" {
				if proc, err := os.FindProcess(pid); err == nil {
					_ = signalHUP(proc)
				}
			}
		}
	}
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	tmp := path + ".sohobotp-tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
