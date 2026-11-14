package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"multiotp-portal/agent/internal/protocol"
)

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{
		{"1.0.1.0", "1.0.2.0", true}, {"1.0.2.0", "1.0.2.0", false}, {"1.0.10.0", "1.0.9.0", false},
		{"1.0.9.0", "1.0.10.0", true}, {"1.0", "1.0.0.1", true}, {"2", "1.9.9.9", false},
	} {
		if got := versionLess(c.a, c.b); got != c.less {
			t.Errorf("versionLess(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func pkgFor(data string, version string) protocol.Package {
	sum := sha256.Sum256([]byte(data))
	return protocol.Package{Version: version, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func TestSigninPlan(t *testing.T) {
	p := &protocol.WindowsPolicy{SigninPackages: map[string]protocol.Package{"amd64": pkgFor("x64 msi", "1.0.2.0"), "arm64": pkgFor("arm msi", "1.0.2.0")}}
	cases := []struct {
		name, arch, installed string
		install               bool
		note, err             string
	}{
		{"not installed: install", "arm64", "", true, "installing SohobOTP Sign-in 1.0.2.0", ""},
		{"older: update", "amd64", "1.0.1.0", true, "updating SohobOTP Sign-in 1.0.1.0 to 1.0.2.0", ""},
		{"same: nothing", "amd64", "1.0.2.0", false, "", ""},
		{"newer installed: kept, never downgraded", "amd64", "1.0.3.0", false, "is newer than the portal's", ""},
		{"no installer for this processor, installed: kept", "386", "1.0.0.0", false, "keeping 1.0.0.0", ""},
		{"no installer for this processor, not installed: error", "386", "", false, "", "no installer for 386"},
	}
	for _, c := range cases {
		pkg, note, err := signinPlan(p, c.arch, c.installed)
		if (pkg != nil) != c.install || !strings.Contains(note, c.note) || (c.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: pkg %v note %q err %v", c.name, pkg, note, err)
		}
		if pkg != nil && pkg.SHA256 != p.SigninPackages[c.arch].SHA256 {
			t.Errorf("%s: wrong installer chosen", c.name)
		}
	}
	if pkg, _, err := signinPlan(&protocol.WindowsPolicy{}, "amd64", ""); pkg != nil || err != nil {
		t.Error("policy without packages: Sign-in is installed by hand, nothing to do")
	}
	bad := &protocol.WindowsPolicy{SigninPackages: map[string]protocol.Package{"amd64": {Version: "1.0.2.0", SHA256: "abc", Size: 10}}}
	if _, _, err := signinPlan(bad, "amd64", ""); err == nil {
		t.Error("an installer without a valid SHA-256 must be refused")
	}
	injected := &protocol.WindowsPolicy{SigninPackages: map[string]protocol.Package{"amd64": pkgFor("x", `1.0" /qn TRANSFORMS=evil`)}}
	if _, _, err := signinPlan(injected, "amd64", ""); err == nil {
		t.Error("a version that is not dotted numbers must be refused")
	}
}

func TestVerifyPackage(t *testing.T) {
	p := pkgFor("the real installer", "1.0.2.0")
	if err := verifyPackage([]byte("the real installer"), &p); err != nil {
		t.Errorf("good installer refused: %v", err)
	}
	if err := verifyPackage([]byte("the real installeR"), &p); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("tampered installer accepted: %v", err)
	}
	if err := verifyPackage([]byte("short"), &p); err == nil {
		t.Error("wrong size accepted")
	}
}
