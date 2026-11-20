//go:build windows

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func defaultDir() string { return filepath.Join(baseDir(), "agent") }

// baseDir is C:\ProgramData\SohobOTP, the parent of the state and requests folders.
func baseDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "SohobOTP")
}

// Permissions of the folders (SDDL): a protected DACL replaces every entry, explicit ones
// included, so nothing another account put there survives.
const (
	sddlFull   = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"       // SYSTEM and Administrators
	sddlLocked = "D:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BA)" // tamper protection: Administrators read
)

// Any standard user can create folders in C:\ProgramData and owns what they create (the
// owner may always change the permissions). So a folder that already exists is used only when
// its owner is SYSTEM, Administrators, TrustedInstaller or the account this program runs as;
// otherwise, or when it is a link (junction, symbolic link), it is moved aside and created
// again. Then owner and permissions are set as a whole.

// ensureDir creates the state folder: SYSTEM and Administrators only (Administrators read
// only under tamper protection, with SYSTEM as owner).
func ensureDir(dir string) error {
	mode, sddl, owner := "full", sddlFull, windows.WELL_KNOWN_SID_TYPE(windows.WinBuiltinAdministratorsSid)
	if locked {
		mode, sddl, owner = "locked", sddlLocked, windows.WinLocalSystemSid
	}
	return secureDir(dir, mode, sddl, owner)
}

// applied remembers the permissions this process set on each folder.
var applied = map[string]string{}

func requestDir() string { return Dir() + "-requests" }

// ensureRequestDir: SYSTEM and Administrators, also under tamper protection (an administrator
// leaves the uninstall request there; the service checks the code itself).
func ensureRequestDir(dir string) error {
	return secureDir(dir, "requests", sddlFull, windows.WinBuiltinAdministratorsSid)
}

func protectFile(string) error { return nil } // inherits the folder ACL

// vetDir is called before the state is read: a folder made by another account is moved aside,
// so nothing it contains (agent.json, enrol-token) is trusted.
func vetDir(dir string) error {
	if applied[dir] != "" {
		return nil
	}
	if underBase(dir) {
		if applied[baseDir()] == "" {
			if _, err := moveAsideIfUntrusted(baseDir()); err != nil {
				return err
			}
		}
	}
	_, err := moveAsideIfUntrusted(dir)
	return err
}

func secureDir(dir, mode, sddl string, owner windows.WELL_KNOWN_SID_TYPE) error {
	if applied[dir] == mode {
		return nil // already set by this process: Save runs often
	}
	if underBase(dir) {
		if applied[baseDir()] == "" {
			if err := makeDir(baseDir(), sddlFull); err != nil {
				return err
			}
			if err := restrict(baseDir(), sddlFull, windows.WinBuiltinAdministratorsSid); err != nil {
				return err
			}
			applied[baseDir()] = "base"
		}
	} else if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err // SOHOBOTP_AGENT_DIR: its parent is not ours to change
	}
	if err := makeDir(dir, sddl); err != nil {
		return err
	}
	if err := restrict(dir, sddl, owner); err != nil {
		return err
	}
	applied[dir] = mode
	return nil
}

func underBase(dir string) bool {
	return strings.EqualFold(filepath.Clean(filepath.Dir(dir)), filepath.Clean(baseDir()))
}

// makeDir creates the folder with its permissions from the start (nobody else can open it in
// between). A folder that is already there is kept only if its owner is trusted.
func makeDir(dir, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(*sa))
		err := windows.CreateDirectory(p, sa)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("cannot create %s: %w", dir, err)
		}
		moved, err := moveAsideIfUntrusted(dir)
		if err != nil {
			return err
		}
		if !moved {
			return nil
		}
	}
	return fmt.Errorf("%s keeps being created by another account", dir)
}

// moveAsideIfUntrusted renames a folder (or link) that another account created; true when it
// was moved. Missing: nothing to do.
func moveAsideIfUntrusted(dir string) (bool, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return false, err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return false, nil
		}
		return false, fmt.Errorf("cannot check %s: %w", dir, err)
	}
	why := ""
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		why = "it is a link"
	} else if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		why = "it is a file"
	} else {
		owner, err := ownerOf(dir)
		if err != nil {
			return false, fmt.Errorf("cannot check the owner of %s: %w", dir, err)
		}
		if trustedOwner(owner) {
			return false, nil
		}
		why = "it was created by another account (" + owner.String() + ")"
	}
	aside := fmt.Sprintf("%s.untrusted-%s", dir, time.Now().Format("20060102-150405.000000000"))
	if err := os.Rename(dir, aside); err != nil {
		return false, fmt.Errorf("%s is not safe to use (%s) and cannot be moved aside: %w; an administrator must delete it", dir, why, err)
	}
	return true, nil
}

func ownerOf(dir string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil, errors.New("no owner")
	}
	return owner, nil
}

const trustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func trustedOwner(owner *windows.SID) bool {
	for _, t := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if owner.IsWellKnown(t) {
			return true
		}
	}
	if ti, err := windows.StringToSid(trustedInstallerSid); err == nil && owner.Equals(ti) {
		return true
	}
	// the account this program runs as (SYSTEM for the service; an administrator, or a test)
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && owner.Equals(u.User.Sid) {
		return true
	}
	return false
}

// restrict sets the owner and the whole DACL (protected: no inherited entries, and every
// explicit entry is replaced). Without the privilege to set the owner (a test run by a plain
// user), only the DACL is set: the owner was checked by makeDir.
func restrict(dir, sddl string, owner windows.WELL_KNOWN_SID_TYPE) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	ownerSid, err := windows.CreateWellKnownSid(owner)
	if err != nil {
		return err
	}
	enableOwnerPrivileges()
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, info|windows.OWNER_SECURITY_INFORMATION, ownerSid, nil, dacl, nil); err == nil {
		return nil
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("cannot restrict %s: %w", dir, err)
	}
	return nil
}

var privilegesTried bool

// enableOwnerPrivileges lets SYSTEM (or an elevated administrator) set any owner.
func enableOwnerPrivileges() {
	if privilegesTried {
		return
	}
	privilegesTried = true
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return
	}
	defer token.Close()
	for _, name := range []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege"} {
		var luid windows.LUID
		n, _ := windows.UTF16PtrFromString(name)
		if windows.LookupPrivilegeValue(nil, n, &luid) != nil {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	}
}
