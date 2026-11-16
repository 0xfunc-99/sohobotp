// Package state stores the agent's identity and progress. The directory is readable
// by root (Linux) or SYSTEM/Administrators (Windows) only; private keys never leave it.
package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/nacl/box"

	"multiotp-portal/agent/internal/protocol"
)

var b64 = base64.StdEncoding

// State is persisted as agent.json in Dir().
type State struct {
	PortalURL       string           `json:"portal_url"`
	CAFile          string           `json:"ca_file,omitempty"`
	EndpointID      string           `json:"endpoint_id"`
	PortalKey       string           `json:"portal_key"`
	SignSeed        string           `json:"sign_seed"`
	BoxPrivate      string           `json:"box_private"`
	BoxPublic       string           `json:"box_public"`
	Applied         protocol.Applied `json:"applied"`
	CheckinInterval int              `json:"checkin_interval"`
	PortalState     string           `json:"portal_state"` // active | pending | disabled | unknown
	LastCheckin     int64            `json:"last_checkin"`
	LastError       string           `json:"last_error"`
	// self-update: a refused version is not retried for an hour
	UpdateFailedVersion string `json:"update_failed_version,omitempty"`
	UpdateFailedAt      int64  `json:"update_failed_at,omitempty"`
	// A configuration that failed to apply (e.g. SohobOTP Sign-in not installed yet, apt
	// locked) is kept as received (signed, secrets still sealed) and retried with a delay.
	RetryConfig *protocol.Envelope `json:"retry_config,omitempty"`
	RetryAt     int64              `json:"retry_at,omitempty"`
	RetryCount  int                `json:"retry_count,omitempty"`
	// Self-update safety (agent/internal/agent/safeupdate.go)
	UpdatePending        *UpdatePending `json:"update_pending,omitempty"`
	UpdateBlockedVersion string         `json:"update_blocked_version,omitempty"`
	// Tamper protection (agent/internal/agent/tamper.go). Protected and the hash come from
	// the last configuration received, also when applying it failed.
	Protected         bool   `json:"protected,omitempty"`
	UninstallCodeHash string `json:"uninstall_code_hash,omitempty"`
	// Locked: this agent locked the machine (service and folder permissions, Uninstall
	// buttons hidden); it unlocks what it locked when the protection is turned off.
	Locked bool `json:"locked,omitempty"`
	// wrong uninstall codes: after MaxCodeFailures the code is refused for a while
	UninstallFailures    int   `json:"uninstall_failures,omitempty"`
	UninstallLockedUntil int64 `json:"uninstall_locked_until,omitempty"`
	// the right code was given: until then the agent may be removed (uninstall, MSI)
	UninstallAllowedUntil int64 `json:"uninstall_allowed_until,omitempty"`
	// Events not yet received by the portal.
	Events []protocol.Event `json:"events,omitempty"`
	// The configuration in force, as received (signed, secrets sealed): with tamper protection
	// the agent applies it again when it finds the machine's settings changed.
	LastConfig *protocol.Envelope `json:"last_config,omitempty"`
	// Running is set while the service runs and removed when it stops normally: found at a
	// start in the same Windows/Linux session, the agent was killed.
	Running *RunMarker `json:"running,omitempty"`
	// Stopped is set when the service is stopped by hand (not at shutdown).
	Stopped *RunMarker `json:"stopped,omitempty"`
	// when an event was last raised, by kind and detail: the same one is not repeated for an hour
	EventSeen map[string]int64 `json:"event_seen,omitempty"`
}

// RunMarker notes when the service started or was stopped, and with which version.
type RunMarker struct {
	At      int64  `json:"at"`
	Version string `json:"version"`
	PID     int    `json:"pid,omitempty"`
}

// UpdatePending is a self-update installed but not yet confirmed by a successful check-in.
type UpdatePending struct {
	From   string `json:"from"`
	To     string `json:"to"`
	At     int64  `json:"at"`
	Starts int    `json:"starts"`
}

// Keys are the endpoint's private keys, loaded from the state.
type Keys struct {
	Sign    ed25519.PrivateKey
	BoxPub  *[32]byte
	BoxPriv *[32]byte
}

// dirOverride lets tests and containers use another folder (SOHOBOTP_AGENT_DIR).
func Dir() string {
	if d := os.Getenv("SOHOBOTP_AGENT_DIR"); d != "" {
		return d
	}
	return defaultDir()
}

func path() string { return filepath.Join(Dir(), "agent.json") }

// NewKeys creates a fresh Ed25519 signing key and X25519 box key pair.
func NewKeys() (*Keys, error) {
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Keys{Sign: sign, BoxPub: pub, BoxPriv: priv}, nil
}

// Store writes the keys into the state (they are saved with it). Private keys are sealed
// with the platform protection (DPAPI machine scope on Windows).
func (s *State) Store(k *Keys) error {
	seed, err := sealKey(k.Sign.Seed())
	if err != nil {
		return fmt.Errorf("cannot protect the signing key: %w", err)
	}
	box, err := sealKey(k.BoxPriv[:])
	if err != nil {
		return fmt.Errorf("cannot protect the encryption key: %w", err)
	}
	s.SignSeed, s.BoxPrivate = seed, box
	s.BoxPublic = b64.EncodeToString(k.BoxPub[:])
	return nil
}

// Keys returns the private keys kept in the state.
func (s *State) Keys() (*Keys, error) {
	seed, err := openKey(s.SignSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing key missing, damaged, or protected for another machine")
	}
	priv, err1 := openKey(s.BoxPrivate)
	pub, err2 := b64.DecodeString(s.BoxPublic)
	if err1 != nil || err2 != nil || len(priv) != 32 || len(pub) != 32 {
		return nil, errors.New("encryption key missing or damaged in the agent state")
	}
	k := &Keys{Sign: ed25519.NewKeyFromSeed(seed), BoxPub: new([32]byte), BoxPriv: new([32]byte)}
	copy(k.BoxPub[:], pub)
	copy(k.BoxPriv[:], priv)
	return k, nil
}

// PortalPublicKey is the pinned portal signing key.
func (s *State) PortalPublicKey() (ed25519.PublicKey, error) {
	key, err := b64.DecodeString(s.PortalKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("pinned portal key missing or damaged in the agent state")
	}
	return key, nil
}

// Exists tells whether the agent is enrolled on this machine.
func Exists() bool {
	_, err := os.Stat(path())
	return err == nil
}

// Load reads the state.
func Load() (*State, error) {
	raw, err := os.ReadFile(path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("the agent is not enrolled on this machine (run install)")
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("agent state damaged: %w", err)
	}
	return &s, nil
}

// Save writes the state atomically, readable by the owner only.
func (s *State) Save() error {
	if err := ensureDir(Dir()); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := protectFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path())
}

// EnsureDir creates the state folder with its restricted permissions (Windows: SYSTEM and
// Administrators only).
func EnsureDir() error { return ensureDir(Dir()) }

// Remove deletes the state directory (uninstall) and the requests folder.
func Remove() error {
	_ = os.RemoveAll(RequestDir())
	return os.RemoveAll(Dir())
}

// RequestDir is where a command run by an administrator leaves a request for the running
// service (uninstall with the code). It is beside the state folder on Windows, where the state
// folder becomes read-only for administrators under tamper protection.
func RequestDir() string { return requestDir() }

// EnsureRequestDir creates the requests folder (root, or SYSTEM and Administrators, only).
func EnsureRequestDir() error { return ensureRequestDir(RequestDir()) }

// SetLocked tells the state folder's permissions to use: with tamper protection on Windows,
// administrators can read it but only SYSTEM (the service) can change it. No effect on Linux.
func SetLocked(on bool) { locked = on }

var locked bool
