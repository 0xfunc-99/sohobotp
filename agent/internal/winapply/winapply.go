// Package winapply writes a SohobOTP Windows policy into the registry values of the
// SohobOTP Sign-in, the Windows sign-in component (HKCR\CLSID\{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31};
// a fork of the multiOTP Credential Provider, same value names).
//
// SohobOTP Sign-in's own installer creates its values; the agent keeps the type of
// every existing value (REG_SZ or REG_DWORD) and only falls back to DWORD for numbers and
// switches and REG_SZ for text when a value does not exist yet. Every write is snapshotted
// and restored if any write fails.
package winapply

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"multiotp-portal/agent/internal/protocol"
)

// KeyPath is the Credential Provider's configuration key under HKEY_CLASSES_ROOT.
const KeyPath = `CLSID\{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31}`

// Kind of a registry value.
type Kind int

const (
	Missing Kind = iota
	String
	DWord
)

// SecretStore keeps the shared secret where only SYSTEM and Administrators can read it
// (HKLM\SOFTWARE\SohobOTP\SignIn on Windows; SohobOTP Sign-in reads it there first). The
// Sign-in key in HKCR is readable by every user, so the secret is removed from it.
type SecretStore interface {
	Secret() (string, error) // "" when not set
	SetSecret(value string) error
}

// LegacySecretValue is where the multiOTP Credential Provider kept the secret (HKCR key).
const LegacySecretValue = "multiOTPSharedSecret"

// Registry is the Credential Provider key (real one on Windows, fake in tests).
type Registry interface {
	Installed() bool
	Get(name string) (kind Kind, s string, n uint32, err error)
	SetString(name, value string) error
	SetDWORD(name string, value uint32) error
	Delete(name string) error
}

// Setting is one registry value the policy sets.
type Setting struct {
	Name    string
	Text    string
	Number  uint32
	Numeric bool // number or switch: DWORD when the value does not exist yet
}

var modeRe = regexp.MustCompile(`^[0-3][ed]$`)

// accountRe: user or DOMAIN\user, without ";" (the separator of sohobotpCodeExempt).
var accountRe = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9.-]{0,62}\\)?[A-Za-z0-9._@$][A-Za-z0-9._@$ -]{0,103}$`)

func boolNum(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// Settings maps a policy to Credential Provider values (portal/docs/agent-protocol.md).
func Settings(p *protocol.WindowsPolicy, secret string) ([]Setting, error) {
	if p.ServerURL == "" || len(p.ServerURL) > 512 {
		return nil, errors.New("policy has no Credential Provider server URL")
	}
	if len(secret) < 16 || len(secret) > 128 {
		return nil, errors.New("Credential Provider secret missing or invalid")
	}
	for _, m := range []string{p.CpusLogon, p.CpusUnlock, p.CpusCredui} {
		if !modeRe.MatchString(m) {
			return nil, fmt.Errorf("invalid Credential Provider mode %q", m)
		}
	}
	if p.ServerTimeout < 1 || p.ServerTimeout > 60 || p.TimeoutUnlock < 0 || p.TimeoutUnlock > 1440 || p.TimeoutReconnect < 0 || p.TimeoutReconnect > 480 {
		return nil, errors.New("timeouts out of range")
	}
	if len(p.CodeExempt) > protocol.MaxAccounts || len(p.CodeExemptAdmin) > protocol.MaxAccounts {
		return nil, errors.New("too many accounts without a code")
	}
	for _, a := range append(append([]string{}, p.CodeExempt...), p.CodeExemptAdmin...) {
		if !accountRe.MatchString(a) {
			return nil, fmt.Errorf("invalid account name %q", a)
		}
	}
	num := func(name string, v uint32) Setting { return Setting{Name: name, Number: v, Numeric: true} }
	txt := func(name, v string) Setting { return Setting{Name: name, Text: v} }
	return []Setting{
		txt("multiOTPServers", p.ServerURL),
		num("multiOTPServerTimeout", uint32(p.ServerTimeout)),
		txt("cpus_logon", p.CpusLogon),
		txt("cpus_unlock", p.CpusUnlock),
		txt("cpus_credui", p.CpusCredui),
		txt("excluded_account", p.ExcludedAccount),
		num("multiOTPCacheEnabled", boolNum(p.CacheEnabled)),
		num("multiOTPUPNFormat", boolNum(p.UPNFormat)),
		txt("multiOTPDefaultPrefix", p.DefaultPrefix),
		num("multiOTPTimeoutUnlock", uint32(p.TimeoutUnlock)),
		num("multiOTPTimeoutReconnect", uint32(p.TimeoutReconnect)),
		num("sohobotpEnrolAtSignIn", boolNum(p.EnrolAtSignIn)),
		txt("sohobotpCodeExempt", strings.Join(p.CodeExempt, ";")),
		txt("sohobotpCodeExemptAdmin", strings.Join(p.CodeExemptAdmin, ";")),
		num("multiOTPWithout2FA", boolNum(p.Without2FA)),
		num("two_step_hide_otp", boolNum(p.TwoStepHideOTP)),
		num("two_step_send_password", boolNum(p.TwoStepSendPassword)),
		txt("login_text", p.LoginText),
		txt("otp_text", p.OTPText),
	}, nil
}

type saved struct {
	name string
	kind Kind
	s    string
	n    uint32
}

// Apply writes the settings, keeping existing value types, and the secret into the protected
// store (removing a readable copy from the Sign-in key); restores everything on failure.
// It returns the names of the values that changed.
func Apply(reg Registry, secrets SecretStore, p *protocol.WindowsPolicy, secret string, dryRun bool) ([]string, error) {
	settings, err := Settings(p, secret)
	if err != nil {
		return nil, err
	}
	if !reg.Installed() {
		return nil, errors.New("SohobOTP Sign-in is not installed (registry key missing): install SohobOTPSignIn.msi first")
	}
	var snaps []saved
	var changed []string
	type write struct {
		set  Setting
		kind Kind
	}
	var writes []write
	for _, s := range settings {
		kind, cur, curN, err := reg.Get(s.Name)
		if err != nil {
			return nil, fmt.Errorf("cannot read %s: %w", s.Name, err)
		}
		target := kind
		if target == Missing {
			target = String
			if s.Numeric {
				target = DWord
			}
		}
		same := false
		switch target {
		case String:
			want := s.Text
			if s.Numeric {
				want = strconv.FormatUint(uint64(s.Number), 10)
			}
			same = kind == String && cur == want
		case DWord:
			if !s.Numeric {
				if _, err := strconv.ParseUint(s.Text, 10, 32); err != nil {
					return nil, fmt.Errorf("%s is a DWORD on this machine but the policy value is text", s.Name)
				}
			}
			same = kind == DWord && curN == numberOf(s)
		}
		if same {
			continue
		}
		snaps = append(snaps, saved{name: s.Name, kind: kind, s: cur, n: curN})
		writes = append(writes, write{s, target})
		changed = append(changed, s.Name)
	}
	currentSecret, err := secrets.Secret()
	if err != nil {
		return nil, fmt.Errorf("cannot read the protected shared secret: %w", err)
	}
	secretChanged := currentSecret != secret
	if secretChanged {
		changed = append(changed, "shared secret (protected key)")
	}
	legacyKind, _, _, err := reg.Get(LegacySecretValue)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", LegacySecretValue, err)
	}
	if legacyKind != Missing {
		changed = append(changed, LegacySecretValue+" removed from the readable key")
	}
	if dryRun || (len(writes) == 0 && !secretChanged && legacyKind == Missing) {
		return changed, nil
	}
	restore := func() {
		for _, s := range snaps {
			switch s.kind {
			case Missing:
				_ = reg.Delete(s.name)
			case String:
				_ = reg.SetString(s.name, s.s)
			case DWord:
				_ = reg.SetDWORD(s.name, s.n)
			}
		}
	}
	for _, w := range writes {
		var err error
		if w.kind == DWord {
			err = reg.SetDWORD(w.set.Name, numberOf(w.set))
		} else if w.set.Numeric {
			err = reg.SetString(w.set.Name, strconv.FormatUint(uint64(w.set.Number), 10))
		} else {
			err = reg.SetString(w.set.Name, w.set.Text)
		}
		if err != nil {
			restore()
			return nil, fmt.Errorf("writing %s failed: %w (previous values restored)", w.set.Name, err)
		}
	}
	if secretChanged {
		if err := secrets.SetSecret(secret); err != nil {
			restore()
			return nil, fmt.Errorf("writing the protected shared secret failed: %w (previous values restored)", err)
		}
	}
	if legacyKind != Missing {
		if err := reg.Delete(LegacySecretValue); err != nil {
			return nil, fmt.Errorf("the shared secret is protected, but its old readable copy could not be removed: %w", err)
		}
	}
	return changed, nil
}

func numberOf(s Setting) uint32 {
	if s.Numeric {
		return s.Number
	}
	n, _ := strconv.ParseUint(s.Text, 10, 32)
	return uint32(n)
}
