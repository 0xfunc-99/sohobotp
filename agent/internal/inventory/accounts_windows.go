//go:build windows

package inventory

import (
	"regexp"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"multiotp-portal/agent/internal/protocol"
)

var (
	netapi32          = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserEnum   = netapi32.NewProc("NetUserEnum")
	procNetApiBufFree = netapi32.NewProc("NetApiBufferFree")
	windowsName       = regexp.MustCompile(`^[^\\/:*?"<>|\x00-\x1f]{1,104}$`)
)

// USER_INFO_1 (lmaccess.h)
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

const (
	filterNormalAccount = 0x0002
	ufAccountDisable    = 0x0002
	userPrivAdmin       = 2
	maxPreferredLength  = 0xFFFFFFFF
	nerrSuccess         = 0
	errorMoreData       = 234
)

// accounts lists enabled local accounts, and directory users with a profile on the machine
// (they have signed in here).
func accounts() []protocol.Account {
	seen := map[string]bool{}
	var out []protocol.Account
	add := func(a protocol.Account) {
		key := strings.ToLower(a.Name)
		if !seen[key] && windowsName.MatchString(strings.ReplaceAll(a.Name, `\`, "")) && len(out) < protocol.MaxAccounts {
			seen[key] = true
			out = append(out, a)
		}
	}
	for _, a := range localAccounts() {
		add(a)
	}
	for _, a := range profileAccounts() {
		add(a)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func localAccounts() []protocol.Account {
	var out []protocol.Account
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		r, _, _ := procNetUserEnum.Call(0, 1, filterNormalAccount, uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if r != nerrSuccess && r != errorMoreData {
			return out
		}
		if buf != nil {
			entries := unsafe.Slice((*userInfo1)(unsafe.Pointer(buf)), read)
			for _, e := range entries {
				if e.Name == nil || e.Flags&ufAccountDisable != 0 {
					continue
				}
				out = append(out, protocol.Account{Name: windows.UTF16PtrToString(e.Name), Kind: "local", Admin: e.Priv == userPrivAdmin})
			}
			procNetApiBufFree.Call(uintptr(unsafe.Pointer(buf)))
		}
		if r != errorMoreData {
			return out
		}
	}
}

// profileAccounts: users with a profile (ProfileList), named DOMAIN\user when not local.
func profileAccounts() []protocol.Account {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	sids, _ := k.ReadSubKeyNames(-1)
	computer, _ := windows.ComputerName()
	var out []protocol.Account
	for _, s := range sids {
		if !strings.HasPrefix(s, "S-1-5-21-") || strings.HasSuffix(s, ".bak") {
			continue // only real accounts (not SYSTEM, LOCAL SERVICE, ...)
		}
		sid, err := windows.StringToSid(s)
		if err != nil {
			continue
		}
		account, domain, use, err := sid.LookupAccount("")
		if err != nil || use != windows.SidTypeUser || account == "" {
			continue
		}
		if strings.EqualFold(domain, computer) {
			continue // local account: already listed, with its admin flag
		}
		out = append(out, protocol.Account{Name: domain + `\` + account, Kind: "domain"})
	}
	return out
}
