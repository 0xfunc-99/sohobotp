package linuxapply

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"multiotp-portal/agent/internal/protocol"
)

const debianSSHD = `# PAM configuration for the Secure Shell service

# Standard Un*x authentication.
@include common-auth

# Disallow non-root logins when /etc/nologin exists.
account    required     pam_nologin.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
@include common-session
@include common-password
`

const debianSudo = `#%PAM-1.0

# Set up user limits from /etc/security/limits.conf.
session    required   pam_limits.so

session    required   pam_env.so readenv=1 user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive
`

const rhelSSHD = `#%PAM-1.0
auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
session    include      password-auth
`

const sshdConfig = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\n"

type fakeSystem struct {
	failSSHD bool
	selinux  string // "" no SELinux tools, "off" / "on": authlogin_radius state, "disabled"
	calls    []string
}

func (f *fakeSystem) Run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name == "sshd" && f.failSSHD {
		return "/etc/ssh/sshd_config.d/50-sohobotp.conf line 3: Bad configuration option", errors.New("exit status 255")
	}
	switch name {
	case "selinuxenabled":
		if f.selinux == "disabled" {
			return "", errors.New("exit status 1")
		}
	case "getsebool":
		return "authlogin_radius --> " + f.selinux + "\n", nil
	}
	return "", nil
}

func (f *fakeSystem) Exists(name string) bool {
	switch name {
	case "sshd":
		return true
	case "getsebool", "setsebool", "selinuxenabled":
		return f.selinux != ""
	}
	return false
}

func TestSELinuxBooleanForRadius(t *testing.T) {
	for _, tc := range []struct {
		state string
		set   bool
	}{{"", false}, {"disabled", false}, {"on", false}, {"off", true}} {
		dir := debian(t)
		sys := &fakeSystem{selinux: tc.state}
		if _, err := (&Applier{Root: dir, Sys: sys}).Apply(policy(), secret); err != nil {
			t.Fatal(err)
		}
		set := strings.Contains(strings.Join(sys.calls, ";"), "setsebool -P authlogin_radius on")
		if set != tc.set {
			t.Fatalf("SELinux %q: setsebool called %v, want %v (%v)", tc.state, set, tc.set, sys.calls)
		}
	}
}

func root(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for path, content := range files {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func debian(t *testing.T) string {
	return root(t, map[string]string{
		"/etc/pam.d/sshd": debianSSHD, "/etc/pam.d/sudo": debianSudo, "/etc/ssh/sshd_config": sshdConfig,
		"/lib/x86_64-linux-gnu/security/pam_radius_auth.so": "",
	})
}

func policy() *protocol.LinuxPolicy {
	return &protocol.LinuxPolicy{
		Enabled: true, RadiusServers: []protocol.RadiusServer{{Host: "radius.example.test", Port: 1812}, {Host: "10.0.0.6", Port: 1645}},
		Timeout: 5, Services: []string{"sshd", "sudo"}, ExcludedUsers: []string{"root", "deploy"},
		ExcludedGroups: []string{"mfa-breakglass"}, SSHKeysNeedCode: true,
	}
}

const secret = "Radius-Secret-For-lin-01-XYZ"

func read(t *testing.T, dir, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, path))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return string(raw)
}

func exists(dir, path string) bool {
	_, err := os.Stat(filepath.Join(dir, path))
	return err == nil
}

func TestModuleFileExclusionsSkipOnlyTheCode(t *testing.T) {
	got := ModuleFile(policy(), "/etc/pam_radius_auth.conf")
	want := managedHeader + `
# Asks for the SohobOTP code after the normal password. Excluded users and groups
# skip only the code line: they still need their normal password.
auth [success=2 default=ignore] pam_succeed_if.so quiet user in root:deploy
auth [success=1 default=ignore] pam_succeed_if.so quiet user ingroup mfa-breakglass
auth required pam_radius_auth.so conf=/etc/pam_radius_auth.conf prompt=code force_prompt
`
	if got != want {
		t.Fatalf("module file:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, "success=done") || strings.Contains(got, "sufficient") {
		t.Fatal("an exclusion must never end the PAM stack with success")
	}
}

func TestRadiusConf(t *testing.T) {
	p := policy()
	p.RadiusServers = append(p.RadiusServers, protocol.RadiusServer{Host: "2001:db8::5", Port: 1812})
	got := RadiusConf(p, secret)
	for _, line := range []string{"radius.example.test:1812\t" + secret + "\t5", "10.0.0.6:1645\t" + secret + "\t5", "[2001:db8::5]:1812\t" + secret + "\t5"} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("missing %q in\n%s", line, got)
		}
	}
}

func TestApplyDebianAndDisableRestoresBytes(t *testing.T) {
	dir := debian(t)
	sys := &fakeSystem{}
	a := &Applier{Root: dir, Sys: sys}
	changes, err := a.Apply(policy(), secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 5 {
		t.Fatalf("expected 5 changes, got %+v", changes)
	}
	sshd := read(t, dir, "/etc/pam.d/sshd")
	if !strings.Contains(sshd, "@include common-auth\n"+marker+"\n"+includeLine+"\n\n# Disallow") {
		t.Fatalf("include not right after the password step:\n%s", sshd)
	}
	if !strings.Contains(read(t, dir, "/etc/pam.d/sudo"), "@include common-auth\n"+marker+"\n"+includeLine+"\n@include common-account") {
		t.Fatal("sudo include misplaced")
	}
	st, _ := os.Stat(filepath.Join(dir, "/etc/pam_radius_auth.conf"))
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 { // no Unix modes on Windows
		t.Fatalf("radius file mode %v", st.Mode().Perm())
	}
	if !strings.Contains(read(t, dir, sshDropIn), "AuthenticationMethods publickey,keyboard-interactive keyboard-interactive") {
		t.Fatal("ssh drop-in")
	}
	if !strings.Contains(strings.Join(sys.calls, ";"), "sshd -t") {
		t.Fatal("sshd -t not run")
	}

	if again, err := a.Apply(policy(), secret); err != nil || len(again) != 0 {
		t.Fatalf("second apply must change nothing: %+v %v", again, err)
	}

	off := &protocol.LinuxPolicy{Enabled: false}
	if _, err := a.Apply(off, ""); err != nil {
		t.Fatal(err)
	}
	if read(t, dir, "/etc/pam.d/sshd") != debianSSHD || read(t, dir, "/etc/pam.d/sudo") != debianSudo {
		t.Fatal("disabling must restore the PAM files byte for byte")
	}
	for _, p := range []string{"/etc/pam.d/" + moduleName, "/etc/pam_radius_auth.conf", sshDropIn} {
		if exists(dir, p) {
			t.Errorf("%s left behind", p)
		}
	}
}

func TestPackageRadiusFileKeptAndRestored(t *testing.T) {
	dir := debian(t)
	original := "# Debian sample\n#server[:port] shared_secret timeout\n"
	if err := os.WriteFile(filepath.Join(dir, "/etc/pam_radius_auth.conf"), []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Applier{Root: dir, Sys: &fakeSystem{}}
	if _, err := a.Apply(policy(), secret); err != nil {
		t.Fatal(err)
	}
	if read(t, dir, "/etc/pam_radius_auth.conf.sohobotp-orig") != original || !strings.HasPrefix(read(t, dir, "/etc/pam_radius_auth.conf"), managedHeader) {
		t.Fatal("original RADIUS file not kept aside")
	}
	if again, err := a.Apply(policy(), secret); err != nil || len(again) != 0 {
		t.Fatalf("second apply must not touch the backup: %+v %v", again, err)
	}
	if _, err := a.Apply(&protocol.LinuxPolicy{Enabled: false}, ""); err != nil {
		t.Fatal(err)
	}
	if read(t, dir, "/etc/pam_radius_auth.conf") != original || exists(dir, "/etc/pam_radius_auth.conf.sohobotp-orig") {
		t.Fatal("original RADIUS file not restored")
	}
}

func TestSSHDCheckFailureRollsBackEverything(t *testing.T) {
	dir := debian(t)
	a := &Applier{Root: dir, Sys: &fakeSystem{failSSHD: true}}
	_, err := a.Apply(policy(), secret)
	if err == nil || !strings.Contains(err.Error(), "previous configuration restored") || !strings.Contains(err.Error(), "Bad configuration option") {
		t.Fatalf("expected a rolled-back sshd -t error, got %v", err)
	}
	if read(t, dir, "/etc/pam.d/sshd") != debianSSHD || read(t, dir, "/etc/pam.d/sudo") != debianSudo {
		t.Fatal("PAM files not restored")
	}
	for _, p := range []string{"/etc/pam.d/" + moduleName, "/etc/pam_radius_auth.conf", sshDropIn} {
		if exists(dir, p) {
			t.Errorf("%s left behind after rollback", p)
		}
	}
}

func TestRefusesWithoutTouchingFiles(t *testing.T) {
	cases := map[string]func(dir string) error{
		"sshd_config without Include": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "/etc/ssh/sshd_config"), []byte("PermitRootLogin no\n"), 0o644)
		},
		"unknown PAM layout": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "/etc/pam.d/sudo"), []byte("auth required pam_unix.so\n"), 0o644)
		},
	}
	for name, breakIt := range cases {
		dir := debian(t)
		if err := breakIt(dir); err != nil {
			t.Fatal(err)
		}
		before := read(t, dir, "/etc/pam.d/sshd")
		if _, err := (&Applier{Root: dir, Sys: &fakeSystem{}}).Apply(policy(), secret); err == nil {
			t.Errorf("%s: expected an error", name)
		}
		if read(t, dir, "/etc/pam.d/sshd") != before || exists(dir, "/etc/pam.d/"+moduleName) {
			t.Errorf("%s: files changed although the policy was refused", name)
		}
	}
}

func TestValidateRefusesUnsafePolicies(t *testing.T) {
	bad := map[string]func(p *protocol.LinuxPolicy){
		"user name with shell characters": func(p *protocol.LinuxPolicy) { p.ExcludedUsers = []string{"a;rm -rf /"} },
		"group with spaces":               func(p *protocol.LinuxPolicy) { p.ExcludedGroups = []string{"domain users"} },
		"host with spaces":                func(p *protocol.LinuxPolicy) { p.RadiusServers[0].Host = "a b" },
		"port out of range":               func(p *protocol.LinuxPolicy) { p.RadiusServers[0].Port = 70000 },
		"unknown service":                 func(p *protocol.LinuxPolicy) { p.Services = []string{"gdm"} },
		"no service":                      func(p *protocol.LinuxPolicy) { p.Services = nil },
		"no server":                       func(p *protocol.LinuxPolicy) { p.RadiusServers = nil },
	}
	for name, mutate := range bad {
		p := policy()
		mutate(p)
		if Validate(p, secret) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if Validate(policy(), "has space inside") == nil || Validate(policy(), "") == nil {
		t.Error("secret with space or empty accepted")
	}
}

func TestServiceRemovedFromPolicyIsRestored(t *testing.T) {
	dir := debian(t)
	a := &Applier{Root: dir, Sys: &fakeSystem{}}
	if _, err := a.Apply(policy(), secret); err != nil {
		t.Fatal(err)
	}
	p := policy()
	p.Services = []string{"sshd"}
	p.SSHKeysNeedCode = false
	if _, err := a.Apply(p, secret); err != nil {
		t.Fatal(err)
	}
	if read(t, dir, "/etc/pam.d/sudo") != debianSudo {
		t.Fatal("sudo not restored when removed from the policy")
	}
	if strings.Contains(read(t, dir, sshDropIn), "AuthenticationMethods") {
		t.Fatal("SSH keys still need the code")
	}
}

func TestRHELLayout(t *testing.T) {
	dir := root(t, map[string]string{
		"/etc/pam.d/sshd": rhelSSHD, "/etc/ssh/sshd_config": sshdConfig, "/etc/redhat-release": "Rocky Linux release 9.4\n",
		"/usr/lib64/security/pam_radius_auth.so": "",
	})
	p := policy()
	p.Services = []string{"sshd"}
	a := &Applier{Root: dir, Sys: &fakeSystem{}}
	if _, err := a.Apply(p, secret); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, dir, "/etc/pam.d/sshd"), "auth       substack     password-auth\n"+marker+"\n"+includeLine+"\nauth       include      postlogin") {
		t.Fatal("RHEL include misplaced")
	}
	if !strings.Contains(read(t, dir, "/etc/pam.d/"+moduleName), "conf=/etc/pam_radius.conf") || !exists(dir, "/etc/pam_radius.conf") {
		t.Fatal("RHEL 9 RADIUS file path (/etc/pam_radius.conf)")
	}
	old := root(t, map[string]string{"/etc/raddb/server": "# EL7\n", "/etc/redhat-release": "CentOS Linux release 7.9\n"})
	if f := (&Applier{Root: old}).RadiusFile(); f != "/etc/raddb/server" {
		t.Fatalf("older RHEL keeps /etc/raddb/server, got %s", f)
	}
}

func TestMissingModuleRefused(t *testing.T) {
	dir := root(t, map[string]string{"/etc/pam.d/sshd": debianSSHD, "/etc/ssh/sshd_config": sshdConfig})
	if _, err := (&Applier{Root: dir, Sys: &fakeSystem{}}).Apply(policy(), secret); err == nil || !strings.Contains(err.Error(), "pam_radius_auth.so") {
		t.Fatalf("expected missing module error, got %v", err)
	}
	if read(t, dir, "/etc/pam.d/sshd") != debianSSHD {
		t.Fatal("changed although the module is missing")
	}
}

func TestDropInSortsBeforeDistributionFiles(t *testing.T) {
	dir := root(t, map[string]string{
		"/etc/pam.d/sshd": rhelSSHD, "/etc/ssh/sshd_config": sshdConfig, "/etc/redhat-release": "Rocky Linux release 9.4\n",
		"/etc/ssh/sshd_config.d/50-redhat.conf":   "ChallengeResponseAuthentication no\n",
		"/etc/ssh/sshd_config.d/50-sohobotp.conf": managedHeader + "\nold name\n",
		"/usr/lib64/security/pam_radius_auth.so":  "",
	})
	p := policy()
	p.Services = []string{"sshd"}
	if _, err := (&Applier{Root: dir, Sys: &fakeSystem{}}).Apply(p, secret); err != nil {
		t.Fatal(err)
	}
	names, _ := os.ReadDir(filepath.Join(dir, "/etc/ssh/sshd_config.d"))
	if len(names) != 2 || names[0].Name() != "00-sohobotp.conf" || names[1].Name() != "50-redhat.conf" {
		t.Fatalf("the agent drop-in must be read first and the old name removed: %v", names)
	}
}

const rhelSudo = `#%PAM-1.0
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    include      system-auth
`

// On RHEL, system-auth has "auth sufficient pam_unix.so": with "include" a right password
// would end the stack before the code is asked. The line must become a substack.
func TestRHELIncludeBecomesSubstackAndIsRestored(t *testing.T) {
	dir := root(t, map[string]string{
		"/etc/pam.d/sshd": rhelSSHD, "/etc/pam.d/sudo": rhelSudo, "/etc/ssh/sshd_config": sshdConfig,
		"/etc/redhat-release": "Rocky Linux release 9.4\n", "/usr/lib64/security/pam_radius_auth.so": "",
	})
	a := &Applier{Root: dir, Sys: &fakeSystem{}}
	if _, err := a.Apply(policy(), secret); err != nil {
		t.Fatal(err)
	}
	sudo := read(t, dir, "/etc/pam.d/sudo")
	want := "#%PAM-1.0\n" + marker + " - replaced: auth       include      system-auth\nauth       substack      system-auth\n" + includeLine + "\naccount    include      system-auth\n"
	if !strings.HasPrefix(sudo, want) {
		t.Fatalf("sudo:\n%s", sudo)
	}
	if strings.Contains(sudo, "account    substack") {
		t.Fatal("only the auth line may change")
	}
	if again, err := a.Apply(policy(), secret); err != nil || len(again) != 0 {
		t.Fatalf("second apply must change nothing: %+v %v", again, err)
	}
	if _, err := a.Apply(&protocol.LinuxPolicy{Enabled: false}, ""); err != nil {
		t.Fatal(err)
	}
	if read(t, dir, "/etc/pam.d/sudo") != rhelSudo || read(t, dir, "/etc/pam.d/sshd") != rhelSSHD {
		t.Fatal("RHEL files not restored byte for byte")
	}
}
