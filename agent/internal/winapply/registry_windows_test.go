//go:build windows

package winapply

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

// TestRealRegistry writes a policy into a throwaway HKCR key with the real Windows registry
// (needs an administrator, as on the CI runner) and checks values and types.
func TestRealRegistry(t *testing.T) {
	path := `CLSID\{B3D2C6A1-5E7F-4C21-9A6E-00000000BEEF}`
	k, _, err := registry.CreateKey(registry.CLASSES_ROOT, path, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if err != nil {
		t.Skipf("cannot create a test key (not an administrator?): %v", err)
	}
	// types as the SohobOTP Sign-in installer leaves them
	_ = k.SetDWordValue("multiOTPServerTimeout", 9)
	_ = k.SetStringValue("multiOTPCacheEnabled", "0")
	k.Close()
	defer registry.DeleteKey(registry.CLASSES_ROOT, path)

	reg := RealRegistry{Path: path}
	if !reg.Installed() {
		t.Fatal("test key not seen as installed")
	}
	if _, err := Apply(reg, policy(), secret, false); err != nil {
		t.Fatal(err)
	}
	k, _ = registry.OpenKey(registry.CLASSES_ROOT, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	defer k.Close()
	if n, typ, err := k.GetIntegerValue("multiOTPServerTimeout"); err != nil || typ != registry.DWORD || n != 5 {
		t.Fatalf("timeout: %d %d %v", n, typ, err)
	}
	if s, typ, err := k.GetStringValue("multiOTPCacheEnabled"); err != nil || typ != registry.SZ || s != "1" {
		t.Fatalf("existing REG_SZ switch: %q %d %v", s, typ, err)
	}
	if n, typ, err := k.GetIntegerValue("multiOTPTimeoutUnlock"); err != nil || typ != registry.DWORD || n != 10 {
		t.Fatalf("new numeric value must be a DWORD: %d %d %v", n, typ, err)
	}
	if s, _, err := k.GetStringValue("multiOTPSharedSecret"); err != nil || s != secret {
		t.Fatalf("secret: %v", err)
	}
	if again, err := Apply(reg, policy(), secret, false); err != nil || len(again) != 0 {
		t.Fatalf("second apply must change nothing: %v %v", again, err)
	}
}
