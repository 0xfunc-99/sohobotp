//go:build windows

package state

import (
	"os"
	"strings"
	"testing"
)

// TestDPAPIKeys: private keys are stored DPAPI-sealed and come back unchanged.
func TestDPAPIKeys(t *testing.T) {
	t.Setenv("SOHOBOTP_AGENT_DIR", t.TempDir())
	keys, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	st := &State{PortalURL: "https://portal.test", EndpointID: "e0000000000000000001"}
	if err := st.Store(keys); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(st.SignSeed, "dpapi:") || !strings.HasPrefix(st.BoxPrivate, "dpapi:") {
		t.Fatal("private keys are not DPAPI-sealed")
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	back, err := loaded.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if !back.Sign.Equal(keys.Sign) || *back.BoxPriv != *keys.BoxPriv {
		t.Fatal("keys changed after DPAPI round trip")
	}
	raw, _ := os.ReadFile(path())
	if strings.Contains(string(raw), b64.EncodeToString(keys.Sign.Seed())) {
		t.Fatal("the plain signing key is in the state file")
	}
}
