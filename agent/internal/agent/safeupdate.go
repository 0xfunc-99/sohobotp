package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/state"
)

// A self-update is made safe in two steps:
//
//  1. Before switching, the downloaded binary must pass "selftest" (right version, opens this
//     agent's keys); otherwise it is never installed.
//  2. After switching, the previous binary is kept as <exe>.previous. If the new version
//     stops MaxStartsBeforeRollback times before its first successful check-in, it moves
//     the previous binary back and exits, so the service manager starts the old version.
//     That version is then never installed again (UpdateBlockedVersion).

// MaxStartsBeforeRollback is how many times an updated agent may start without having
// checked in successfully before it rolls back.
const MaxStartsBeforeRollback = 3

// crashAfterStartForTests makes the agent panic right after its start-up checks. Set only
// by the end-to-end test build (-ldflags -X); empty in every real build.
var crashAfterStartForTests string

func previousPath(exe string) string { return exe + ".previous" }
func failedPath(exe string) string   { return exe + ".failed" }

// candidatePath is where a downloaded release waits for its self-test. Windows only runs
// files ending in .exe.
func candidatePath(exe string) string {
	if strings.HasSuffix(strings.ToLower(exe), ".exe") {
		return strings.TrimSuffix(exe, exe[len(exe)-4:]) + ".new.exe"
	}
	return exe + ".new"
}

// selfTestCandidate runs the downloaded binary once ("selftest") with a timeout.
func selfTestCandidate(path, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "selftest", "--expect-version", version).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "selftest ok "+version) {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("the new version does not start (selftest: %v %s)", err, msg)
	}
	return nil
}

// installCandidate switches to the tested binary, keeping the running one as .previous.
func installCandidate(exe, candidate string) error {
	_ = os.Remove(previousPath(exe))
	if err := os.Rename(exe, previousPath(exe)); err != nil { // allowed while running (Windows too)
		return err
	}
	if err := os.Rename(candidate, exe); err != nil {
		_ = os.Rename(previousPath(exe), exe)
		return err
	}
	return nil
}

// StartupCheck runs before anything else when the agent starts (service, run --once).
// It returns true when the agent has rolled back to the previous binary: the caller must
// exit so that the previous version is started.
func StartupCheck(st *state.State, exe string, now int64, log func(string, ...any)) bool {
	p := st.UpdatePending
	if p == nil {
		return false
	}
	if inventory.Version != p.To {
		// the previous binary is running again (after a roll back, or a reinstall)
		st.UpdatePending = nil
		_ = st.Save()
		return false
	}
	p.Starts++
	if p.Starts <= MaxStartsBeforeRollback {
		_ = st.Save()
		return false
	}
	if _, err := os.Stat(previousPath(exe)); err != nil {
		log("UPDATE: %s stopped %d times, but the previous binary is gone: cannot roll back", p.To, p.Starts-1)
		st.UpdatePending = nil
		_ = st.Save()
		return false
	}
	_ = os.Remove(failedPath(exe))
	if err := os.Rename(exe, failedPath(exe)); err != nil {
		log("UPDATE: roll back failed: %v", err)
		return false
	}
	if err := os.Rename(previousPath(exe), exe); err != nil {
		_ = os.Rename(failedPath(exe), exe)
		log("UPDATE: roll back failed: %v", err)
		return false
	}
	st.UpdateBlockedVersion = p.To
	st.LastError = fmt.Sprintf("update to %s rolled back to %s: it stopped %d times before checking in", p.To, p.From, p.Starts-1)
	st.UpdatePending = nil
	_ = st.Save()
	log("UPDATE: %s", st.LastError)
	return true
}

// confirmUpdate: the updated agent has checked in successfully, the update is kept.
func (a *Agent) confirmUpdate() {
	p := a.St.UpdatePending
	if p == nil || inventory.Version != p.To {
		return
	}
	a.St.UpdatePending = nil
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(previousPath(exe))
		_ = os.Remove(failedPath(exe))
	}
	a.Log("update to %s confirmed (checked in)", p.To)
}

// CrashHookForTests panics in the end-to-end test build only (see crashAfterStartForTests).
func CrashHookForTests() {
	if crashAfterStartForTests == "yes" {
		panic("test build: crash after start")
	}
}
