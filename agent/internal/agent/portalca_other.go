//go:build !windows

package agent

// syncPortalCA: SohobOTP Sign-in exists on Windows only.
func syncPortalCA([]byte, func(string, ...any)) {}
