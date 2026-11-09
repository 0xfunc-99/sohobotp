package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func signed(t *testing.T, data []byte, version string) (*Manifest, string, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(data)
	m := &Manifest{Version: version, OS: "linux", Arch: "amd64", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	if err := Sign(m, priv); err != nil {
		t.Fatal(err)
	}
	return m, base64.StdEncoding.EncodeToString(pub), priv
}

func TestSignVerifyAndBinary(t *testing.T) {
	data := []byte("new agent binary")
	m, pub, _ := signed(t, data, "0.2.0")
	if err := Verify(m, pub); err != nil {
		t.Fatal(err)
	}
	if err := CheckBinary(m, data); err != nil {
		t.Fatal(err)
	}
	if CheckBinary(m, []byte("new agent binarY")) == nil || CheckBinary(m, append(data, 'x')) == nil {
		t.Fatal("tampered or longer binary accepted")
	}
}

func TestRefusals(t *testing.T) {
	data := []byte("binary")
	m, pub, _ := signed(t, data, "0.2.0")
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if Verify(m, base64.StdEncoding.EncodeToString(otherPub)) == nil {
		t.Error("manifest signed by another key accepted")
	}
	if Verify(m, "") == nil {
		t.Error("agent without release key must not update")
	}
	for name, mutate := range map[string]func(c *Manifest){
		"version changed":  func(c *Manifest) { c.Version = "9.9.9" },
		"platform changed": func(c *Manifest) { c.OS = "windows" },
		"hash changed":     func(c *Manifest) { c.SHA256 = c.SHA256[:62] + "00" },
		"size changed":     func(c *Manifest) { c.Size++ },
	} {
		c := *m
		mutate(&c)
		if Verify(&c, pub) == nil {
			t.Errorf("%s: signature still accepted", name)
		}
	}
	bad := *m
	bad.Version = "1.2"
	if bad.Validate() == nil {
		t.Error("bad version format accepted")
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.2.0", "0.1.9", true}, {"0.10.0", "0.9.0", true}, {"0.1.0", "0.1.0", false}, {"0.1.0", "0.2.0", false}, {"1.0.0", "0.99.99", true}} {
		if Newer(c.a, c.b) != c.want {
			t.Errorf("Newer(%s, %s) != %v", c.a, c.b, c.want)
		}
	}
}

// TestMessageMatchesPortal pins the signed bytes; portal/tests/unit.php checks the same string.
func TestMessageMatchesPortal(t *testing.T) {
	m := &Manifest{Version: "0.2.0", OS: "linux", Arch: "amd64", SHA256: "ABCDEF" + strings.Repeat("0", 58), Size: 19}
	want := "sohobotp-release-v1\nlinux\namd64\n0.2.0\nabcdef" + strings.Repeat("0", 58) + "\n19"
	if string(m.Message()) != want {
		t.Fatalf("release message format changed:\n%q", m.Message())
	}
}
