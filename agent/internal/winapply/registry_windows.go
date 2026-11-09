//go:build windows

package winapply

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// RealRegistry is the Credential Provider key in HKEY_CLASSES_ROOT (64-bit view).
type RealRegistry struct{}

func open(access uint32) (registry.Key, error) {
	return registry.OpenKey(registry.CLASSES_ROOT, KeyPath, access|registry.WOW64_64KEY)
}

func (RealRegistry) Installed() bool {
	k, err := open(registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func (RealRegistry) Get(name string) (Kind, string, uint32, error) {
	k, err := open(registry.QUERY_VALUE)
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

func (RealRegistry) SetString(name, value string) error {
	k, err := open(registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}

func (RealRegistry) SetDWORD(name string, value uint32) error {
	k, err := open(registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, value)
}

func (RealRegistry) Delete(name string) error {
	k, err := open(registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.DeleteValue(name)
}
