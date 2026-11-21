package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/release"
)

// testReleaseKey stands for the offline release key in these tests.
var testReleaseKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// withReleaseKey builds the agent "with" the test release key for one test.
func withReleaseKey(t *testing.T) {
	old := release.PublicKey
	release.PublicKey = base64.StdEncoding.EncodeToString(testReleaseKey.Public().(ed25519.PublicKey))
	t.Cleanup(func() { release.PublicKey = old })
}

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

// pkgFor: a Sign-in installer for arch, signed with the test release key.
func pkgFor(data, version, arch string) protocol.Package {
	sum := sha256.Sum256([]byte(data))
	p := protocol.Package{Version: version, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	m := &release.PackageManifest{Kind: "signin", Arch: arch, Version: p.Version, SHA256: p.SHA256, Size: p.Size}
	if release.SignPackage(m, testReleaseKey) == nil {
		p.Signature = m.Signature
	}
	return p
}

func TestSigninPlan(t *testing.T) {
	withReleaseKey(t)
	p := &protocol.WindowsPolicy{SigninPackages: map[string]protocol.Package{"amd64": pkgFor("x64 msi", "1.0.2.0", "amd64"), "arm64": pkgFor("arm msi", "1.0.2.0", "arm64")}}
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
	injected := &protocol.WindowsPolicy{SigninPackages: map[string]protocol.Package{"amd64": pkgFor("x", `1.0" /qn TRANSFORMS=evil`, "amd64")}}
	if _, _, err := signinPlan(injected, "amd64", ""); err == nil {
		t.Error("a version that is not dotted numbers must be refused")
	}
}

func TestVerifyPackage(t *testing.T) {
	p := pkgFor("the real installer", "1.0.2.0", "amd64")
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

// TestSigninPlanNeedsReleaseSignature: the policy (signed by the portal) is not enough: an
// installer runs only with the offline release key's signature, for this processor.
func TestSigninPlanNeedsReleaseSignature(t *testing.T) {
	withReleaseKey(t)
	unsigned := pkgFor("evil msi", "9.0.0.0", "amd64")
	unsigned.Signature = ""
	other := pkgFor("x64 msi", "1.0.2.0", "arm64") // signed, but for ARM
	_, otherKey, _ := ed25519.GenerateKey(nil)
	forged := pkgFor("evil msi", "9.0.0.0", "amd64")
	m := &release.PackageManifest{Kind: "signin", Arch: "amd64", Version: forged.Version, SHA256: forged.SHA256, Size: forged.Size}
	_ = release.SignPackage(m, otherKey)
	forged.Signature = m.Signature
	for name, pkg := range map[string]protocol.Package{"unsigned": unsigned, "signed for another processor": other, "signed with another key": forged} {
		if got, _, err := signinPlan(&protocol.WindowsPolicy{SigninPackages: map[string]protocol.Package{"amd64": pkg}}, "amd64", ""); got != nil || err == nil {
			t.Errorf("%s installer accepted", name)
		}
	}
	release.PublicKey = ""
	if got, _, err := signinPlan(&protocol.WindowsPolicy{SigninPackages: map[string]protocol.Package{"amd64": pkgFor("x64 msi", "1.0.2.0", "amd64")}}, "amd64", ""); got != nil || err == nil {
		t.Error("an agent built without a release key must install nothing by itself")
	}
}
