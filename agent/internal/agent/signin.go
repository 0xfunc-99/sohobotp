package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/release"
)

// SohobOTP Sign-in installed by the agent (computer policy "Install and update SohobOTP Sign-in
// automatically"). The policy names the installer for each processor with its version, size
// and SHA-256; the agent downloads it from the portal over the signed agent channel, checks it,
// and runs it silently. The decisions are here (tested on every OS), the Windows part in
// signin_windows.go.

// packageSource downloads an installer from the portal (set by Load).
var packageSource func(protocol.PackageRequest, int64) ([]byte, error)

func setPackageSource(f func(protocol.PackageRequest, int64) ([]byte, error)) { packageSource = f }

// maxPackage is the largest installer accepted (Sign-in is about 20 MB, the VC++ runtime 25 MB).
const maxPackage = 200 << 20

// versionLess compares dotted version numbers ("1.0.10.0" > "1.0.9.0"). Missing parts are 0;
// a part that is not a number compares as 0.
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// validPackage refuses a policy entry the agent could not check (no hash, absurd size).
func validPackage(p *protocol.Package) error {
	if p == nil {
		return fmt.Errorf("no installer")
	}
	if raw, err := hex.DecodeString(p.SHA256); err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("installer without a valid SHA-256")
	}
	if p.Size <= 0 || p.Size > maxPackage {
		return fmt.Errorf("installer size %d out of range", p.Size)
	}
	if p.Version == "" || strings.Trim(p.Version, "0123456789.") != "" {
		return fmt.Errorf("installer version %q not valid", p.Version)
	}
	return nil
}

// verifyPackage checks a downloaded installer against the signed policy.
func verifyPackage(data []byte, p *protocol.Package) error {
	if int64(len(data)) != p.Size {
		return fmt.Errorf("downloaded installer is %d bytes, %d expected", len(data), p.Size)
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), p.SHA256) {
		return fmt.Errorf("downloaded installer does not match its SHA-256: not installed")
	}
	return nil
}

// checkPackageSignature: the installer must be signed with the release key built into this
// agent (the portal's own signature on the policy is not enough: it would let whoever controls
// the portal run any program as SYSTEM on every computer).
func checkPackageSignature(kind, arch string, p *protocol.Package) error {
	return release.VerifyPackage(&release.PackageManifest{Kind: kind, Arch: arch, Version: p.Version, SHA256: strings.ToLower(p.SHA256), Size: p.Size, Signature: p.Signature}, release.PublicKey)
}

// signinPlan decides what to do for this machine: the installer to run (nil: nothing) and a
// note for the log. installed is the installed Sign-in version ("" when not installed).
func signinPlan(p *protocol.WindowsPolicy, arch, installed string) (*protocol.Package, string, error) {
	if len(p.SigninPackages) == 0 {
		return nil, "", nil // installed by hand
	}
	pkg, ok := p.SigninPackages[arch]
	if !ok {
		if installed != "" {
			return nil, "no SohobOTP Sign-in installer for " + arch + " on the portal, keeping " + installed, nil
		}
		return nil, "", fmt.Errorf("SohobOTP Sign-in is not installed and the portal has no installer for %s", arch)
	}
	if err := validPackage(&pkg); err != nil {
		return nil, "", err
	}
	if err := checkPackageSignature("signin", arch, &pkg); err != nil {
		return nil, "", err
	}
	switch {
	case installed == "":
		return &pkg, "installing SohobOTP Sign-in " + pkg.Version, nil
	case versionLess(installed, pkg.Version):
		return &pkg, "updating SohobOTP Sign-in " + installed + " to " + pkg.Version, nil
	case versionLess(pkg.Version, installed):
		return nil, "SohobOTP Sign-in " + installed + " is newer than the portal's " + pkg.Version + ": kept", nil
	}
	return nil, "", nil // up to date
}
