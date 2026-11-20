//go:build windows

package state

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
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

// TestExplicitEntriesRemoved: an entry someone added to a folder that already exists (here
// Users full control) does not survive: the whole DACL is replaced.
func TestExplicitEntriesRemoved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", dir, "/grant", "*S-1-5-32-545:(OI)(CI)F").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	if err := ensureDir(dir); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if s := sd.String(); strings.Contains(s, ";;;BU)") || !strings.Contains(s, "D:P") {
		t.Fatalf("users still have access or DACL not protected: %s", s)
	}
}

// TestLinkMovedAside: a junction in place of the state folder is moved aside, never followed.
func TestLinkMovedAside(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	dir := filepath.Join(root, "agent")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	if err := ensureDir(dir); err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(dir)
	attrs, err := windows.GetFileAttributes(p)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatalf("state folder is still a link (attrs %x, %v)", attrs, err)
	}
	if moved, _ := filepath.Glob(dir + ".untrusted-*"); len(moved) != 1 {
		t.Fatalf("link not moved aside: %v", moved)
	}
}
