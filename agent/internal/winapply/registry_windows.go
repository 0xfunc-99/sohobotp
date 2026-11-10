//go:build windows

package winapply

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SecretKeyPath is the protected key read first by SohobOTP Sign-in for the shared secret.
const SecretKeyPath = `SOFTWARE\SohobOTP\SignIn`

// protectedDACL: SYSTEM and Administrators only, nothing inherited (users cannot read).
const protectedDACL = "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)"

// RealSecretStore is HKLM\SOFTWARE\SohobOTP\SignIn (64-bit view). Path is SecretKeyPath when
// empty (tests use another key).
type RealSecretStore struct{ Path string }

func (s RealSecretStore) path() string {
	if s.Path == "" {
		return SecretKeyPath
	}
	return s.Path
}

func (s RealSecretStore) Secret() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, s.path(), registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(LegacySecretValue)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return v, err
}

// SetSecret creates the key with its protected DACL (set again every time) and writes the value.
func (s RealSecretStore) SetSecret(value string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, s.path(), registry.ALL_ACCESS|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	sd, err := windows.SecurityDescriptorFromString(protectedDACL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	return k.SetStringValue(LegacySecretValue, value)
}

// RealRegistry is the SohobOTP Sign-in key in HKEY_CLASSES_ROOT (64-bit view). Path is
// KeyPath when empty (tests use another key).
type RealRegistry struct{ Path string }

func (r RealRegistry) open(access uint32) (registry.Key, error) {
	path := r.Path
	if path == "" {
		path = KeyPath
	}
	return registry.OpenKey(registry.CLASSES_ROOT, path, access|registry.WOW64_64KEY)
}

func (r RealRegistry) Installed() bool {
	k, err := r.open(registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func (r RealRegistry) Get(name string) (Kind, string, uint32, error) {
	k, err := r.open(registry.QUERY_VALUE)
	if err != nil {
		return Missing, "", 0, err
	}
	defer k.Close()
	_, typ, err := k.GetValue(name, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return Missing, "", 0, nil
	}
	if err != nil && !errors.Is(err, registry.ErrShortBuffer) {
		return Missing, "", 0, err
	}
	switch typ {
	case registry.DWORD:
		n, _, err := k.GetIntegerValue(name)
		return DWord, "", uint32(n), err
	default:
		s, _, err := k.GetStringValue(name)
		return String, s, 0, err
	}
}

func (r RealRegistry) SetString(name, value string) error {
	k, err := r.open(registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}

func (r RealRegistry) SetDWORD(name string, value uint32) error {
	k, err := r.open(registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, value)
}

func (r RealRegistry) Delete(name string) error {
	k, err := r.open(registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.DeleteValue(name)
}
