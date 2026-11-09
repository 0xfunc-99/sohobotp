//go:build windows

package winapply

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

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
