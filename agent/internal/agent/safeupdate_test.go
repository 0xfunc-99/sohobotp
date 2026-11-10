package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
)

func pendingState(t *testing.T, to string) *state.State {
	t.Helper()
	t.Setenv("SOHOBOTP_AGENT_DIR", t.TempDir())
	st := &state.State{EndpointID: "e0000000000000000001", Applied: protocol.Applied{Status: "none"},
		UpdatePending: &state.UpdatePending{From: "0.1.0", To: to}}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	return st
}

func binaries(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "sohobotp-agent")
	os.WriteFile(exe, []byte("NEW"), 0o755)
	os.WriteFile(previousPath(exe), []byte("OLD"), 0o755)
	return exe
}

func TestRollbackAfterRepeatedStartsWithoutCheckin(t *testing.T) {
	st := pendingState(t, inventory.Version) // this binary is the updated one
	exe := binaries(t)
	nolog := func(string, ...any) {}
	for i := 1; i <= MaxStartsBeforeRollback; i++ {
		if StartupCheck(st, exe, 0, nolog) {
			t.Fatalf("rolled back after %d starts, want after %d", i, MaxStartsBeforeRollback)
		}
	}
	if !StartupCheck(st, exe, 0, nolog) {
		t.Fatal("no roll back after the starts without check-in")
	}
	if b, _ := os.ReadFile(exe); string(b) != "OLD" {
		t.Fatalf("previous binary not restored: %q", b)
	}
	if b, _ := os.ReadFile(failedPath(exe)); string(b) != "NEW" {
		t.Fatal("failed binary not kept aside")
	}
	if st.UpdateBlockedVersion != inventory.Version || st.UpdatePending != nil || st.LastError == "" {
		t.Fatalf("state after roll back: %+v", st)
	}
	saved, _ := state.Load()
	if saved.UpdateBlockedVersion != inventory.Version {
		t.Fatal("blocked version not saved")
	}
}

func TestStartsAreCountedAcrossRestarts(t *testing.T) {
	st := pendingState(t, inventory.Version)
	exe := binaries(t)
	StartupCheck(st, exe, 0, func(string, ...any) {})
	saved, _ := state.Load()
	if saved.UpdatePending == nil || saved.UpdatePending.Starts != 1 {
		t.Fatalf("start not saved: %+v", saved.UpdatePending)
	}
}

func TestCheckinConfirmsTheUpdate(t *testing.T) {
	a, _, _ := setup(t)
	a.St.UpdatePending = &state.UpdatePending{From: "0.0.9", To: inventory.Version, Starts: 2}
	if _, err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if a.St.UpdatePending != nil {
		t.Fatal("successful check-in did not confirm the update")
	}
}

func TestPreviousVersionRunningClearsPending(t *testing.T) {
	st := pendingState(t, "9.9.9") // the update target, but the old binary is the one running
	exe := binaries(t)
	if StartupCheck(st, exe, 0, func(string, ...any) {}) || st.UpdatePending != nil {
		t.Fatal("pending update not cleared while the previous version runs")
	}
}

func TestBlockedVersionNotOfferedAgain(t *testing.T) {
	a, _, _ := setup(t)
	a.St.UpdateBlockedVersion = "9.9.9"
	a.update(&protocol.Update{Version: "9.9.9", OS: runtime.GOOS, Arch: runtime.GOARCH})
	if a.Updated != "" || a.St.LastError != "" {
		t.Fatalf("blocked version tried again: %q %q", a.Updated, a.St.LastError)
	}
}

func TestCandidatePath(t *testing.T) {
	if got := candidatePath(`C:\Program Files\SohobOTP\Agent\sohobotp-agent.exe`); got != `C:\Program Files\SohobOTP\Agent\sohobotp-agent.new.exe` {
		t.Fatal(got)
	}
	if got := candidatePath("/usr/local/sbin/sohobotp-agent"); got != "/usr/local/sbin/sohobotp-agent.new" {
		t.Fatal(got)
	}
}
