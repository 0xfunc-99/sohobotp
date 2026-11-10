package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/release"
	"multiotp-portal/agent/internal/state"
)

// update applies a signed release offered by the portal. Nothing is downloaded unless the
// signature (release key built into this agent) and the version are right; the binary is
// replaced only if its size and SHA-256 match the signed values. A refused version is not
// retried for an hour.
func (a *Agent) update(u *protocol.Update) {
	if u.OS != runtime.GOOS || u.Arch != runtime.GOARCH || !release.Newer(u.Version, inventory.Version) {
		return // not for this machine, or not newer: never downgrade
	}
	now := a.now().Unix()
	if a.St.UpdateFailedVersion == u.Version && now-a.St.UpdateFailedAt < 3600 {
		return
	}
	if a.St.UpdateBlockedVersion == u.Version {
		return // rolled back once: never again (publish a fixed version)
	}
	fail := func(err error) {
		a.St.UpdateFailedVersion, a.St.UpdateFailedAt = u.Version, now
		a.St.LastError = fmt.Sprintf("update to %s refused: %v", u.Version, err)
		a.Log("UPDATE: %s", a.St.LastError)
	}
	m := &release.Manifest{Version: u.Version, OS: u.OS, Arch: u.Arch, SHA256: u.SHA256, Size: u.Size, Signature: u.Signature}
	if err := release.Verify(m, release.PublicKey); err != nil {
		fail(err)
		return
	}
	data, err := a.Client.Download(a.St.EndpointID, a.Keys.Sign, protocol.ReleaseRequest{Version: u.Version, OS: u.OS, Arch: u.Arch}, m.Size)
	if err != nil {
		fail(err)
		return
	}
	if err := release.CheckBinary(m, data); err != nil {
		fail(err)
		return
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		fail(err)
		return
	}
	candidate := candidatePath(exe)
	if err := os.WriteFile(candidate, data, 0o755); err != nil {
		fail(err)
		return
	}
	if err := selfTestCandidate(candidate, u.Version); err != nil {
		_ = os.Remove(candidate)
		fail(err)
		return
	}
	if err := installCandidate(exe, candidate); err != nil {
		_ = os.Remove(candidate)
		fail(err)
		return
	}
	a.St.UpdatePending = &state.UpdatePending{From: inventory.Version, To: u.Version, At: now}
	a.Log("updated %s -> %s (self-test passed), restarting", inventory.Version, u.Version)
	a.Updated = u.Version
}
