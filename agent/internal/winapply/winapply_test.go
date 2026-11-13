package winapply

import (
	"errors"
	"strings"
	"testing"

	"multiotp-portal/agent/internal/protocol"
)

type value struct {
	kind Kind
	s    string
	n    uint32
}

type fakeRegistry struct {
	installed bool
	values    map[string]value
	failOn    string
}

func (f *fakeRegistry) Installed() bool { return f.installed }
func (f *fakeRegistry) Get(name string) (Kind, string, uint32, error) {
	v, ok := f.values[name]
	if !ok {
		return Missing, "", 0, nil
	}
	return v.kind, v.s, v.n, nil
}
func (f *fakeRegistry) SetString(name, s string) error {
	if name == f.failOn {
		return errors.New("access denied")
	}
	f.values[name] = value{kind: String, s: s}
	return nil
}
func (f *fakeRegistry) SetDWORD(name string, n uint32) error {
	if name == f.failOn {
		return errors.New("access denied")
	}
	f.values[name] = value{kind: DWord, n: n}
	return nil
}
func (f *fakeRegistry) Delete(name string) error { delete(f.values, name); return nil }

func policy() *protocol.WindowsPolicy {
	return &protocol.WindowsPolicy{
		ServerURL: "https://portal.example.test/portal/cp.php?e=e8f2c1a9b4d7e6f5a3c2", ServerTimeout: 5,
		CpusLogon: "0e", CpusUnlock: "0e", CpusCredui: "1d", ExcludedAccount: `PC01\breakglass`,
		CacheEnabled: true, LoginText: "SohobOTP", TimeoutUnlock: 10, TimeoutReconnect: 15, EnrolAtSignIn: true, CodeExempt: []string{"svc-backup", `EXAMPLE\deploy`},
	}
}

const secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeSecrets struct {
	value string
	fail  bool
}

func (f *fakeSecrets) Secret() (string, error) { return f.value, nil }
func (f *fakeSecrets) SetSecret(v string) error {
	if f.fail {
		return errors.New("access denied")
	}
	f.value = v
	return nil
}

// installedByMSI mimics the values the CP installer creates (types as found on a machine).
func installedByMSI() *fakeRegistry {
	return &fakeRegistry{installed: true, values: map[string]value{
		"multiOTPServers": {kind: String, s: "https://192.168.1.88"}, "multiOTPSharedSecret": {kind: String, s: "ClientServerSecret"},
		"multiOTPServerTimeout": {kind: DWord, n: 5}, "multiOTPCacheEnabled": {kind: String, s: "0"},
		"cpus_logon": {kind: String, s: "0e"}, "login_text": {kind: String, s: ""},
	}}
}

func TestApplyKeepsExistingTypes(t *testing.T) {
	reg := installedByMSI()
	secrets := &fakeSecrets{}
	changed, err := Apply(reg, secrets, policy(), secret, false)
	if err != nil {
		t.Fatal(err)
	}
	if reg.values["multiOTPCacheEnabled"] != (value{kind: String, s: "1"}) {
		t.Fatalf("existing REG_SZ switch must stay a string: %+v", reg.values["multiOTPCacheEnabled"])
	}
	if reg.values["multiOTPServerTimeout"] != (value{kind: DWord, n: 5}) {
		t.Fatal("server timeout must stay a DWORD")
	}
	if secrets.value != secret || !strings.Contains(reg.values["multiOTPServers"].s, "cp.php?e=") {
		t.Fatal("gateway URL and own secret not written")
	}
	if _, ok := reg.values["multiOTPSharedSecret"]; ok {
		t.Fatal("the secret must be removed from the Sign-in key (readable by every user)")
	}
	if reg.values["sohobotpCodeExempt"] != (value{kind: String, s: `svc-backup;EXAMPLE\deploy`}) {
		t.Fatalf("accounts without a code not written: %+v", reg.values["sohobotpCodeExempt"])
	}
	if reg.values["sohobotpEnrolAtSignIn"] != (value{kind: DWord, n: 1}) {
		t.Fatalf("set-up at sign-in not written: %+v", reg.values["sohobotpEnrolAtSignIn"])
	}
	if reg.values["multiOTPTimeoutReconnect"] != (value{kind: DWord, n: 15}) {
		t.Fatalf("reconnect grace not written: %+v", reg.values["multiOTPTimeoutReconnect"])
	}
	if reg.values["multiOTPTimeoutUnlock"] != (value{kind: DWord, n: 10}) || reg.values["cpus_credui"] != (value{kind: String, s: "1d"}) {
		t.Fatalf("missing values must be created with the default type: %+v %+v", reg.values["multiOTPTimeoutUnlock"], reg.values["cpus_credui"])
	}
	for _, name := range changed {
		if name == "multiOTPServerTimeout" || name == "cpus_logon" {
			t.Errorf("%s was already right and must not be rewritten", name)
		}
	}
	if again, err := Apply(reg, secrets, policy(), secret, false); err != nil || len(again) != 0 {
		t.Fatalf("second apply must change nothing: %v %v", again, err)
	}
}

func TestFailedSecretWriteRestoresEveryValue(t *testing.T) {
	reg := installedByMSI()
	before := map[string]value{}
	for k, v := range reg.values {
		before[k] = v
	}
	if _, err := Apply(reg, &fakeSecrets{fail: true}, policy(), secret, false); err == nil || !strings.Contains(err.Error(), "previous values restored") {
		t.Fatalf("expected a restored failure, got %v", err)
	}
	for k, v := range before {
		if reg.values[k] != v {
			t.Errorf("%s not restored: %+v", k, reg.values[k])
		}
	}
}

func TestFailedWriteRestoresEveryValue(t *testing.T) {
	reg := installedByMSI()
	before := map[string]value{}
	for k, v := range reg.values {
		before[k] = v
	}
	reg.failOn = "login_text"
	if _, err := Apply(reg, &fakeSecrets{}, policy(), secret, false); err == nil || !strings.Contains(err.Error(), "previous values restored") {
		t.Fatalf("expected a restored failure, got %v", err)
	}
	if len(reg.values) != len(before) {
		t.Fatalf("values created by the failed apply were not removed: %d vs %d", len(reg.values), len(before))
	}
	for k, v := range before {
		if reg.values[k] != v {
			t.Errorf("%s not restored: %+v", k, reg.values[k])
		}
	}
}

func TestRefusals(t *testing.T) {
	if _, err := Apply(&fakeRegistry{values: map[string]value{}}, &fakeSecrets{}, policy(), secret, false); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("missing Credential Provider must be refused: %v", err)
	}
	bad := map[string]func(p *protocol.WindowsPolicy){
		"mode":               func(p *protocol.WindowsPolicy) { p.CpusLogon = "9x" },
		"no URL":             func(p *protocol.WindowsPolicy) { p.ServerURL = "" },
		"timeout":            func(p *protocol.WindowsPolicy) { p.ServerTimeout = 0 },
		"unlock 2 d":         func(p *protocol.WindowsPolicy) { p.TimeoutUnlock = 2880 },
		"reconnect 9 h":      func(p *protocol.WindowsPolicy) { p.TimeoutReconnect = 540 },
		"reconnect negative": func(p *protocol.WindowsPolicy) { p.TimeoutReconnect = -1 },
		"exempt injection":   func(p *protocol.WindowsPolicy) { p.CodeExempt = []string{"alice;bob"} },
	}
	for name, mutate := range bad {
		p := policy()
		mutate(p)
		if _, err := Apply(installedByMSI(), &fakeSecrets{}, p, secret, false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Apply(installedByMSI(), &fakeSecrets{}, policy(), "short", false); err == nil {
		t.Error("short secret accepted")
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	reg := installedByMSI()
	changed, err := Apply(reg, &fakeSecrets{}, policy(), secret, true)
	if err != nil || len(changed) == 0 {
		t.Fatalf("dry run: %v %v", changed, err)
	}
	if reg.values["multiOTPSharedSecret"].s != "ClientServerSecret" {
		t.Fatal("dry run wrote to the registry")
	}
}
