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
	platforms = map[string]bool{"linux/amd64": true, "linux/arm64": true, "windows/amd64": true}
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
