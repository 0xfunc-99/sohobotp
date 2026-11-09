//go:build !windows

package state

// On Linux the state file itself is the protection (root only, 0600).
func sealKey(raw []byte) (string, error) { return b64.EncodeToString(raw), nil }

func openKey(s string) ([]byte, error) { return b64.DecodeString(s) }
