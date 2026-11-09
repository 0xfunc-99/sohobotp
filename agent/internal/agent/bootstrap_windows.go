//go:build windows

package agent

import (
	"golang.org/x/sys/windows/registry"
)

// BootstrapKey holds the values the MSI writes (properties PORTAL, TOKEN, PIN, CAFILE).
const BootstrapKey = `SOFTWARE\SohobOTP\Agent`

func readBootstrap() (Enrolment, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, BootstrapKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return Enrolment{}, ErrNoBootstrap
	}
	defer k.Close()
	get := func(name string) string { v, _, _ := k.GetStringValue(name); return v }
	e := Enrolment{Portal: get("Portal"), Token: get("Token"), Pin: get("Pin"), CAFile: get("CAFile")}
	if e.Portal == "" || e.Token == "" || e.Pin == "" {
		return Enrolment{}, ErrNoBootstrap
	}
	return e, nil
}

// clearBootstrapToken removes the enrolment token once used: it must not stay readable.
func clearBootstrapToken() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, BootstrapKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue("Token")
}
