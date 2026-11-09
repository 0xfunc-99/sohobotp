//go:build windows

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"multiotp-portal/agent/internal/state"
)

// BootstrapKey holds the values the MSI writes (properties PORTAL, PIN, CAFILE). The token
// (property TOKEN) is not written there: HKLM\SOFTWARE is readable by every user and Windows
// Installer logs registry-table values. The MSI runs "save-token" instead (a custom action
// hidden from the log), which keeps it in the state folder (SYSTEM and Administrators only).
const BootstrapKey = `SOFTWARE\SohobOTP\Agent`

func tokenFile() string { return filepath.Join(state.Dir(), "enrol-token") }

// SaveBootstrapToken stores the MSI's enrolment token for the service's first enrolment.
// Nothing is stored when the machine is already enrolled (repair or upgrade).
func SaveBootstrapToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("empty token")
	}
	if state.Exists() {
		return nil
	}
	if err := state.EnsureDir(); err != nil {
		return err
	}
	return os.WriteFile(tokenFile(), []byte(token), 0o600)
}

func readBootstrap() (Enrolment, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, BootstrapKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return Enrolment{}, ErrNoBootstrap
	}
	defer k.Close()
	get := func(name string) string { v, _, _ := k.GetStringValue(name); return v }
	e := Enrolment{Portal: get("Portal"), Pin: get("Pin"), CAFile: get("CAFile")}
	if raw, err := os.ReadFile(tokenFile()); err == nil {
		e.Token = strings.TrimSpace(string(raw))
	} else {
		e.Token = get("Token") // written by hand or by an older MSI
	}
	if e.Portal == "" || e.Token == "" || e.Pin == "" {
		return Enrolment{}, ErrNoBootstrap
	}
	return e, nil
}

// clearBootstrapToken removes the enrolment token once used: it must not stay on disk.
func clearBootstrapToken() {
	_ = os.Remove(tokenFile())
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, BootstrapKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue("Token")
}
