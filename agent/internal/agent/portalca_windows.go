//go:build windows

package agent

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"

	"multiotp-portal/agent/internal/winapply"
)

// syncPortalCA writes the certificate authority that verified the portal into the SohobOTP
// Sign-in folder (portal-ca.pem). Sign-in's engine then checks the portal's certificate with
// it (windows-signin/patch-engine.ps1): Sign-in only talks to the portal this agent trusts.
// The folder is readable by SYSTEM and Administrators only (Sign-in installer).
func syncPortalCA(der []byte, log func(string, ...any)) {
	if len(der) == 0 {
		return
	}
	kind, dir, _, err := (winapply.RealRegistry{}).Get("multiOTPPath")
	if err != nil || kind != winapply.String || dir == "" {
		return // SohobOTP Sign-in not installed
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(dir, "portal-ca.pem")
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log("SohobOTP Sign-in: cannot write %s: %v", path, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		log("SohobOTP Sign-in: cannot write %s: %v", path, err)
		return
	}
	log("SohobOTP Sign-in pinned to the portal's certificate authority (%s)", path)
}
