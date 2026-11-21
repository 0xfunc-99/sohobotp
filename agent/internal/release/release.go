// Package release signs and verifies agent releases (self-update, stage 4d).
//
// Releases are signed with an Ed25519 release key that is kept OFFLINE, never on the portal.
// Agents carry the release public key compiled in (-X .../release.PublicKey=...), so a
// compromised portal can stop updates but cannot make machines run other code.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PublicKey is the release public key (base64), set at build time. Empty: updates disabled.
var PublicKey = ""

// Fingerprint is a short name for the release key built into this agent (the first 8 bytes of
// its SHA-256, hex), "" when the build has none. It is reported to the portal, which shows the
// computers that cannot update themselves.
func Fingerprint() string {
	raw, err := base64.StdEncoding.DecodeString(PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// Manifest describes one signed agent binary.
type Manifest struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Signature string `json:"signature"`
}

var (
	versionRe = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}$`)
	platforms = map[string]bool{"linux/amd64": true, "linux/arm64": true, "windows/amd64": true, "windows/arm64": true}
)

// Message is the exact byte string a release signature covers.
func (m *Manifest) Message() []byte {
	return []byte(fmt.Sprintf("sohobotp-release-v1\n%s\n%s\n%s\n%s\n%d", m.OS, m.Arch, m.Version, strings.ToLower(m.SHA256), m.Size))
}

// Validate checks the manifest fields (not the signature).
func (m *Manifest) Validate() error {
	if !versionRe.MatchString(m.Version) {
		return fmt.Errorf("invalid version %q (use x.y.z)", m.Version)
	}
	if !platforms[m.OS+"/"+m.Arch] {
		return fmt.Errorf("unsupported platform %s/%s", m.OS, m.Arch)
	}
	if raw, err := hex.DecodeString(m.SHA256); err != nil || len(raw) != sha256.Size {
		return errors.New("invalid sha256")
	}
	if m.Size <= 0 || m.Size > 200<<20 {
		return errors.New("invalid size")
	}
	return nil
}

// Sign fills the signature with the release private key.
func Sign(m *Manifest, key ed25519.PrivateKey) error {
	if err := m.Validate(); err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, m.Message()))
	return nil
}

// Verify checks a manifest against a release public key (base64).
func Verify(m *Manifest, publicKey string) error {
	if publicKey == "" {
		return errors.New("this agent build has no release key: self-update is disabled")
	}
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("the built-in release key is invalid")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(pub, m.Message(), sig) {
		return errors.New("release signature is not valid for the built-in release key")
	}
	return nil
}

// CheckBinary verifies downloaded bytes against the manifest.
func CheckBinary(m *Manifest, data []byte) error {
	if int64(len(data)) != m.Size {
		return fmt.Errorf("download size %d differs from the signed size %d", len(data), m.Size)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(m.SHA256) {
		return errors.New("download does not match the signed SHA-256")
	}
	return nil
}

// Newer tells whether version a is strictly newer than b (x.y.z).
func Newer(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parts(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(v, ".", 3) {
		if i < 3 {
			out[i], _ = strconv.Atoi(p)
		}
	}
	return out
}

// PackageManifest describes an installer the agent runs as SYSTEM (SohobOTP Sign-in, the Visual
// C++ runtime), signed with the same offline release key as the agent itself: the portal only
// passes it on, so neither a compromised portal nor a portal administrator can make computers
// run another program.
type PackageManifest struct {
	Kind      string `json:"kind"` // signin | vcredist
	Arch      string `json:"arch"` // amd64 | arm64 (vcredist: amd64)
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Signature string `json:"signature"`
}

var packageVersionRe = regexp.MustCompile(`^\d{1,5}(\.\d{1,5}){1,3}$`)

// Message is the exact byte string a package signature covers.
func (m *PackageManifest) Message() []byte {
	return []byte(fmt.Sprintf("sohobotp-package-v1\n%s\n%s\n%s\n%s\n%d", m.Kind, m.Arch, m.Version, strings.ToLower(m.SHA256), m.Size))
}

// Validate checks the manifest fields (not the signature).
func (m *PackageManifest) Validate() error {
	switch m.Kind + "/" + m.Arch {
	case "signin/amd64", "signin/arm64", "vcredist/amd64":
	default:
		return fmt.Errorf("unsupported installer %s/%s", m.Kind, m.Arch)
	}
	if !packageVersionRe.MatchString(m.Version) {
		return fmt.Errorf("invalid installer version %q", m.Version)
	}
	if raw, err := hex.DecodeString(m.SHA256); err != nil || len(raw) != sha256.Size {
		return errors.New("invalid sha256")
	}
	if m.Size <= 0 || m.Size > 200<<20 {
		return errors.New("invalid size")
	}
	return nil
}

// SignPackage fills the signature with the release private key.
func SignPackage(m *PackageManifest, key ed25519.PrivateKey) error {
	if err := m.Validate(); err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, m.Message()))
	return nil
}

// VerifyPackage checks an installer's manifest against the release public key (base64).
func VerifyPackage(m *PackageManifest, publicKey string) error {
	if publicKey == "" {
		return errors.New("this agent build has no release key: it installs no programs by itself")
	}
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("the built-in release key is invalid")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(pub, m.Message(), sig) {
		return fmt.Errorf("the %s installer %s is not signed with the release key built into this agent: not installed", m.Kind, m.Version)
	}
	return nil
}
