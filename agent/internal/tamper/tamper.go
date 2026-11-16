// Package tamper holds what tamper protection needs on every OS: the uninstall code check.
//
// With tamper protection (a computer policy in the portal) the agent is only removed with the
// computer's uninstall code. The portal shows the code to an administrator; the machine only
// ever receives its hash, inside the signed configuration, so the code cannot be read from
// the machine. The check works without a network connection.
package tamper

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Iterations of PBKDF2-HMAC-SHA256: the code has 60 random bits, the iterations make
	// guessing it from a copied hash slower still.
	Iterations = 100000
	saltPrefix = "sohobotp-uninstall-v1\n"
)

// Normalise accepts the code as an administrator types it: any case, with or without the
// dashes and spaces between its groups.
func Normalise(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "").Replace(strings.TrimSpace(code)))
}

// Hash is the value the portal puts into the policy for this endpoint and code (hex).
func Hash(endpointID, code string) string {
	sum := pbkdf2.Key([]byte(Normalise(code)), []byte(saltPrefix+endpointID), Iterations, sha256.Size, sha256.New)
	return hex.EncodeToString(sum)
}

// Check tells whether code is the uninstall code behind hash. An empty or malformed hash
// never matches: a protected machine without a usable hash cannot be uninstalled by code
// (turn tamper protection off in the portal instead).
func Check(hash, endpointID, code string) bool {
	want, err := hex.DecodeString(hash)
	if err != nil || len(want) != sha256.Size || Normalise(code) == "" {
		return false
	}
	got, _ := hex.DecodeString(Hash(endpointID, code))
	return subtle.ConstantTimeCompare(want, got) == 1
}
