// Package protocol implements the SohobOTP agent <-> portal protocol, version 1
// (portal/docs/agent-protocol.md). The wire identifiers keep their historical
// "multiotp-" names: they are covered by the libsodium test vectors.
package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

const (
	enrollPrefix  = "multiotp-agent-enroll-v1"
	requestPrefix = "multiotp-agent-v1"
	configPrefix  = "multiotp-config-v1\n"
)

var b64 = base64.StdEncoding

// Inventory is reported at enrolment and at every check-in.
type Inventory struct {
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	OSName       string    `json:"os_name"`
	OSVersion    string    `json:"os_version"`
	Kernel       string    `json:"kernel"`
	Arch         string    `json:"arch"`
	Domain       string    `json:"domain"`
	IPs          []string  `json:"ips"`
	AgentVersion string    `json:"agent_version"`
	Component    Component `json:"component"`
	Accounts     []Account `json:"accounts,omitempty"`
}

// Account is a user account that can sign in on the machine: local accounts with a login
// (Linux: a real shell; Windows: enabled local accounts) and, on Windows, directory users with
// a profile on the machine. The portal shows them on the machine's page, where the
// administrator chooses who needs a code.
type Account struct {
	Name  string `json:"name"`  // Linux: user; Windows: user (local) or DOMAIN\user
	Kind  string `json:"kind"`  // local | domain
	Admin bool   `json:"admin"` // uid 0 / sudo or wheel group; Windows: administrator
}

// MaxAccounts bounds the list sent at each check-in.
const MaxAccounts = 300

// Component is the login component the agent manages (pam_radius, multiotp-cp).
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Applied is the result of the last configuration applied on the machine.
type Applied struct {
	Version int    `json:"version"`
	Status  string `json:"status"` // applied | failed | none
	Error   string `json:"error"`
	At      *int64 `json:"at"`
}

// EnrollRequest is the body of a=enroll.
type EnrollRequest struct {
	Token     string    `json:"token"`
	SignKey   string    `json:"sign_key"`
	BoxKey    string    `json:"box_key"`
	Proof     string    `json:"proof"`
	Inventory Inventory `json:"inventory"`
}

// EnrollReply is the answer to a=enroll.
type EnrollReply struct {
	EndpointID      string `json:"endpoint_id"`
	PortalKey       string `json:"portal_key"`
	CheckinInterval int    `json:"checkin_interval"`
}

// CheckinRequest is the body of a=checkin.
type CheckinRequest struct {
	Inventory Inventory `json:"inventory"`
	Applied   Applied   `json:"applied"`
}

// CheckinReply is the answer to a=checkin. Unknown fields are ignored.
type CheckinReply struct {
	CheckinInterval int       `json:"checkin_interval"`
	State           string    `json:"state"` // active | pending
	Config          *Envelope `json:"config"`
	Update          *Update   `json:"update"`
}

// Update offers a signed agent release (stage 4d). The signature is checked against the
// release key built into the agent, never against the portal key.
type Update struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Signature string `json:"signature"`
}

// ReleaseRequest is the body of a=release (signed): which binary to download.
type ReleaseRequest struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Envelope is a signed configuration (section 4).
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Config is a verified configuration payload, with its secrets opened.
type Config struct {
	EndpointID string            `json:"endpoint_id"`
	Version    int               `json:"version"`
	IssuedAt   int64             `json:"issued_at"`
	OS         string            `json:"os"`
	Policy     json.RawMessage   `json:"policy"`
	Secrets    map[string]string `json:"secrets"`
}

// LinuxPolicy is the policy for os=linux.
type LinuxPolicy struct {
	Enabled         bool           `json:"enabled"`
	RadiusServers   []RadiusServer `json:"radius_servers"`
	Timeout         int            `json:"timeout"`
	Services        []string       `json:"services"`
	ExcludedUsers   []string       `json:"excluded_users"`
	ExcludedGroups  []string       `json:"excluded_groups"`
	SSHKeysNeedCode bool           `json:"ssh_keys_need_code"`
}

// RadiusServer is one FreeRADIUS server, in failover order.
type RadiusServer struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// WindowsPolicy is the policy for os=windows (SohobOTP Sign-in).
type WindowsPolicy struct {
	ServerURL           string   `json:"server_url"`
	ServerTimeout       int      `json:"server_timeout"`
	CpusLogon           string   `json:"cpus_logon"`
	CpusUnlock          string   `json:"cpus_unlock"`
	CpusCredui          string   `json:"cpus_credui"`
	ExcludedAccount     string   `json:"excluded_account"`
	CacheEnabled        bool     `json:"cache_enabled"`
	UPNFormat           bool     `json:"upn_format"`
	DefaultPrefix       string   `json:"default_prefix"`
	TimeoutUnlock       int      `json:"timeout_unlock"`
	TimeoutReconnect    int      `json:"timeout_reconnect"` // minutes; 0 when an older portal leaves it out
	EnrolAtSignIn       bool     `json:"enrol_at_signin"`   // QR code on the sign-in screen for users without an authenticator
	CodeExempt          []string `json:"code_exempt"`       // accounts that sign in on this machine with their password only
	Without2FA          bool     `json:"without2fa"`
	TwoStepHideOTP      bool     `json:"two_step_hide_otp"`
	TwoStepSendPassword bool     `json:"two_step_send_password"`
	LoginText           string   `json:"login_text"`
	OTPText             string   `json:"otp_text"`
}

// EnrollMessage is the exact byte string signed by the enrolment proof.
func EnrollMessage(token string, signPub ed25519.PublicKey, boxPub *[32]byte) []byte {
	return []byte(enrollPrefix + "\n" + token + "\n" + b64.EncodeToString(signPub) + "\n" + b64.EncodeToString(boxPub[:]))
}

// RequestMessage is the exact byte string signed for every request (section 2).
func RequestMessage(method, uri, time, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(requestPrefix + "\n" + method + "\n" + uri + "\n" + time + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
}

// Pin is the lowercase hex SHA-256 of the portal public key.
func Pin(portalKey ed25519.PublicKey) string {
	sum := sha256.Sum256(portalKey)
	return hex.EncodeToString(sum[:])
}

// NormalisePin accepts the pin as shown on the enrolment page (groups separated by spaces).
func NormalisePin(pin string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", ":", "", "-", "").Replace(strings.TrimSpace(pin)))
}

// Errors returned by OpenConfig. They never contain secret material.
var (
	ErrSignature = errors.New("configuration signature is not valid for the pinned portal key")
	ErrEndpoint  = errors.New("configuration is for another endpoint")
	ErrOS        = errors.New("configuration is for another operating system")
	ErrRollback  = errors.New("configuration version is not newer than the applied one (replay or rollback)")
	ErrSecret    = errors.New("a secret in the configuration cannot be opened with this endpoint's key")
)

// OpenConfig verifies an envelope like section 4 requires and opens its secrets.
// Nothing is returned unless every check passes.
func OpenConfig(env *Envelope, portalKey ed25519.PublicKey, endpointID, goos string, lastApplied int, boxPub, boxPriv *[32]byte) (*Config, error) {
	payload, err := b64.DecodeString(env.Payload)
	if err != nil {
		return nil, ErrSignature
	}
	sig, err := b64.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || len(portalKey) != ed25519.PublicKeySize {
		return nil, ErrSignature
	}
	if !ed25519.Verify(portalKey, append([]byte(configPrefix), payload...), sig) {
		return nil, ErrSignature
	}
	var cfg Config
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return nil, fmt.Errorf("configuration payload is not valid JSON: %w", err)
	}
	if cfg.EndpointID != endpointID {
		return nil, ErrEndpoint
	}
	if cfg.OS != goos {
		return nil, ErrOS
	}
	if cfg.Version <= lastApplied {
		return nil, ErrRollback
	}
	opened := make(map[string]string, len(cfg.Secrets))
	for name, sealed := range cfg.Secrets {
		raw, err := b64.DecodeString(sealed)
		if err != nil {
			return nil, ErrSecret
		}
		plain, ok := box.OpenAnonymous(nil, raw, boxPub, boxPriv)
		if !ok {
			return nil, ErrSecret
		}
		opened[name] = string(plain)
	}
	cfg.Secrets = opened
	return &cfg, nil
}
