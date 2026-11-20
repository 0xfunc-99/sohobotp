//go:build windows

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"multiotp-portal/agent/internal/winapply"
)

// eraseSigninCache deletes the users and tokens SohobOTP Sign-in's engine keeps for offline
// sign-in (users\*.db, tokens\*.db in its folder, named by the multiOTPPath value). Sign-in is
// a client of the portal only: these files are nothing but that offline copy.
func eraseSigninCache() (int, error) {
	k, err := registry.OpenKey(registry.CLASSES_ROOT, winapply.KeyPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, nil // Sign-in not installed: nothing kept
	}
	dir, _, err := k.GetStringValue("multiOTPPath")
	k.Close()
	if err != nil || dir == "" {
		return 0, nil
	}
	erased := 0
	var failed error
	for _, sub := range []string{"users", "tokens"} {
		files, _ := filepath.Glob(filepath.Join(dir, sub, "*.db"))
		for _, f := range files {
			if err := os.Remove(f); err != nil {
				failed = errors.Join(failed, err)
				continue
			}
			erased++
		}
	}
	return erased, failed
}

var procWTSLogoffSession = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSLogoffSession")

// signOutSessions signs out every session that has a user (console, Remote Desktop,
// disconnected ones too). Session 0 (services) has none.
func signOutSessions() (int, error) {
	var list *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &list, &count); err != nil {
		return 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(list)))
	out := 0
	var failed error
	for _, s := range unsafe.Slice(list, count) {
		if s.SessionID == 0 || (s.State != windows.WTSActive && s.State != windows.WTSDisconnected) {
			continue
		}
		var token windows.Token
		if windows.WTSQueryUserToken(s.SessionID, &token) != nil {
			continue // nobody signed in there
		}
		token.Close()
		if r, _, err := procWTSLogoffSession.Call(0, uintptr(s.SessionID), 0); r == 0 {
			failed = errors.Join(failed, err)
			continue
		}
		out++
	}
	return out, failed
}
