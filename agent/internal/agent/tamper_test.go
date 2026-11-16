package agent

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
	"multiotp-portal/agent/internal/tamper"
)

const testCode = "ABCD-EFGH-JKLM"

// quietApplier answers like a real applier: NoChange unless told that something differed.
type quietApplier struct {
	summary string
	err     error
	applies int
}

func (q *quietApplier) Apply(*protocol.Config) (string, error) {
	q.applies++
	if q.err != nil {
		return "", q.err
	}
	if q.summary != "" {
		return q.summary, nil
	}
	return NoChange, nil
}

// protected returns an agent whose portal turned tamper protection on (one check-in done).
func protected(t *testing.T) (*Agent, *fakePortal, *quietApplier) {
	// the test machine may have no SohobOTP Sign-in (Windows CI): not what these tests look at
	signinMissing = func() bool { return false }
	t.Cleanup(func() { signinMissing = componentMissing })
	a, fp, _ := setup(t)
	q := &quietApplier{}
	a.Applier = q
	fp.policy = map[string]any{"enabled": true, "tamper_protection": true, "uninstall_code_hash": tamper.Hash(a.St.EndpointID, testCode)}
	if _, err := a.Once(); err != nil {
		t.Fatal(err)
	}
	if !a.St.Protected || a.St.UninstallCodeHash == "" || a.St.LastConfig == nil {
		t.Fatalf("protection not taken from the configuration: %+v", a.St)
	}
	return a, fp, q
}

func kinds(events []protocol.Event) string {
	var k []string
	for _, e := range events {
		k = append(k, e.Kind)
	}
	return strings.Join(k, ",")
}

func TestProtectionFollowsTheConfiguration(t *testing.T) {
	a, fp, _ := protected(t)
	a.Once()
	if !fp.seen.Inventory.Protected {
		t.Fatal("the portal is not told that the machine is protected")
	}
	fp.version, fp.policy = 2, map[string]any{"enabled": true}
	a.Once()
	if a.St.Protected || a.St.UninstallCodeHash != "" {
		t.Fatal("protection not turned off by a newer configuration")
	}
	if err := RemovalAllowed(); err != nil {
		t.Fatalf("unprotected machine: %v", err)
	}
}

func TestProtectionAppliesEvenWhenTheRestFails(t *testing.T) {
	a, fp, _ := setup(t)
	q := &quietApplier{err: os.ErrPermission}
	a.Applier = q
	fp.policy = map[string]any{"enabled": true, "tamper_protection": true, "uninstall_code_hash": tamper.Hash(a.St.EndpointID, testCode)}
	a.Once()
	if a.St.Applied.Status != "failed" || !a.St.Protected {
		t.Fatalf("a failed apply must still protect: %+v", a.St.Applied)
	}
}

func TestUninstallCodeAndLockout(t *testing.T) {
	a, _, _ := protected(t)
	now := time.Now().Unix()
	if err := checkCode(a.St, now, ""); err != ErrCodeNeeded {
		t.Fatalf("no code: %v", err)
	}
	if a.St.UninstallFailures != 0 {
		t.Fatal("a missing code must not count as a wrong one")
	}
	for i := 0; i < MaxCodeFailures; i++ {
		if err := checkCode(a.St, now, "WRNG-WRNG-WRNG"); err != ErrWrongCode {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if err := checkCode(a.St, now, testCode); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("the right code must wait after %d wrong ones: %v", MaxCodeFailures, err)
	}
	if err := checkCode(a.St, now+codeLockSeconds, "abcdefghjklm"); err != nil {
		t.Fatalf("right code after the wait: %v", err)
	}
}

func request(t *testing.T, id, code string) {
	t.Helper()
	if err := state.EnsureRequestDir(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(uninstallRequest{ID: id, Code: code})
	if err := os.WriteFile(requestFile(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func answer(t *testing.T, id string) uninstallAnswer {
	t.Helper()
	raw, err := os.ReadFile(answerFile(id))
	if err != nil {
		t.Fatal(err)
	}
	var out uninstallAnswer
	json.Unmarshal(raw, &out)
	return out
}

func TestServiceAnswersUninstallRequests(t *testing.T) {
	a, fp, _ := protected(t)
	if err := RemovalAllowed(); err != ErrCodeNeeded {
		t.Fatalf("protected machine: forget must be refused, got %v", err)
	}
	request(t, "00000000000000aa", "WRNG-WRNG-WRNG")
	if !a.watch() {
		t.Fatal("request not handled")
	}
	if got := answer(t, "00000000000000aa"); got.OK || got.Message != ErrWrongCode.Error() {
		t.Fatalf("wrong code answered %+v", got)
	}
	if kinds(fp.events) != protocol.EventUninstallRefused {
		t.Fatalf("the portal must hear of the attempt at once, got %q", kinds(fp.events))
	}
	if len(a.St.Events) != 0 {
		t.Fatal("events received by the portal must leave the queue")
	}
	request(t, "00000000000000ab", testCode)
	a.watch()
	if got := answer(t, "00000000000000ab"); !got.OK {
		t.Fatalf("right code refused: %+v", got)
	}
	if kinds(fp.events) != protocol.EventUninstallRefused+","+protocol.EventUninstalled {
		t.Fatalf("events %q", kinds(fp.events))
	}
	if err := RemovalAllowed(); err != nil {
		t.Fatalf("after the right code the agent may be removed: %v", err)
	}
	if err := AuthoriseUninstall(""); err != nil {
		t.Fatalf("the MSI's check after the code: %v", err)
	}
	if _, err := os.Stat(requestFile()); err == nil {
		t.Fatal("the request (it holds the code) was left on disk")
	}
	// the window closes again: protected as before
	a.now = func() time.Time { return time.Now().Add(time.Duration(uninstallWindow+1) * time.Second) }
	a.watch()
	if !protectedNow(a.St, a.now().Unix()) || !a.St.Locked {
		t.Fatal("protection must come back when the agent was not removed in time")
	}
}

func TestOldOrMalformedRequestsAreIgnored(t *testing.T) {
	a, fp, _ := protected(t)
	request(t, "not-an-id", testCode)
	a.watch()
	request(t, "00000000000000ac", testCode)
	old := time.Now().Add(-10 * time.Minute)
	os.Chtimes(requestFile(), old, old)
	a.watch()
	if err := RemovalAllowed(); err != ErrCodeNeeded || len(fp.events) != 0 {
		t.Fatalf("a malformed or stale request was honoured: %v %q", err, kinds(fp.events))
	}
}

func TestDriftIsPutBackAndReported(t *testing.T) {
	a, fp, q := protected(t)
	base := q.applies
	a.lastDrift = 0
	a.watch()
	if q.applies != base+1 || len(a.St.Events) != 0 {
		t.Fatalf("an untouched machine: one check, no event (applies %d, events %q)", q.applies-base, kinds(a.St.Events))
	}
	a.watch()
	if q.applies != base+1 {
		t.Fatal("the settings are checked once a minute, not at every look")
	}
	q.summary = "Credential Provider values set: cpus_logon"
	a.lastDrift = 0
	a.watch()
	a.lastDrift = 0
	a.watch() // the same change again within the hour: one event
	a.Once()
	if kinds(fp.events) != protocol.EventSettingsRestored || !strings.Contains(fp.events[0].Detail, "cpus_logon") {
		t.Fatalf("events %q", kinds(fp.events))
	}
	q.summary, q.err = "", os.ErrPermission
	a.lastDrift = 0
	a.watch()
	a.Once()
	if !strings.HasSuffix(kinds(fp.events), protocol.EventProtectionBroken) {
		t.Fatalf("events %q", kinds(fp.events))
	}
	// SohobOTP Sign-in removed by hand, installed again by the applier: reported as such
	q.err = nil
	signinMissing = func() bool { return true }
	a.lastDrift = 0
	a.watch()
	a.Once()
	if !strings.HasSuffix(kinds(fp.events), protocol.EventSigninRemoved) {
		t.Fatalf("Sign-in removal not reported: %q", kinds(fp.events))
	}
}

func TestEventsAreKeptUntilThePortalHasThem(t *testing.T) {
	a, fp, _ := protected(t)
	a.event(protocol.EventServiceChanged, "x")
	fp.mode = "disabled"
	a.Once()
	if len(a.St.Events) != 1 {
		t.Fatal("an event was dropped although the check-in failed")
	}
	saved, _ := state.Load()
	if len(saved.Events) != 1 {
		t.Fatal("events not saved (lost on restart)")
	}
	fp.mode = "active"
	a.Once()
	if len(a.St.Events) != 0 || kinds(fp.events) != protocol.EventServiceChanged+","+protocol.EventServiceChanged {
		t.Fatalf("events %q, %d left", kinds(fp.events), len(a.St.Events))
	}
	for i := 0; i < protocol.MaxEvents+20; i++ {
		addEvent(a.St, time.Now().Unix(), protocol.EventServiceChanged, strings.Repeat("y", i+1))
	}
	if len(a.St.Events) != protocol.MaxEvents {
		t.Fatalf("%d events kept", len(a.St.Events))
	}
}

func TestKilledAndStoppedAreReportedAtTheNextStart(t *testing.T) {
	a, _, _ := protected(t)
	if bootTime() == 0 {
		t.Skip("boot time unknown on this system")
	}
	now := time.Now().Unix()
	// stopped normally: nothing
	a.started()
	a.ended()
	a.started()
	if len(a.St.Events) != 0 {
		t.Fatalf("a normal stop was reported: %q", kinds(a.St.Events))
	}
	// the process disappeared (marker left), same system session
	a.started()
	if kinds(a.St.Events) != protocol.EventAgentKilled {
		t.Fatalf("killed agent not reported: %q", kinds(a.St.Events))
	}
	// marker from before the last boot: the machine was switched off, not the agent killed
	a.St.Events, a.St.EventSeen = nil, nil
	a.St.Running = &state.RunMarker{At: bootTime() - 100, Version: inventory.Version}
	a.started()
	// another version (an upgrade replaced the program): not reported
	a.St.Running = &state.RunMarker{At: now, Version: "0.0.1"}
	a.started()
	if len(a.St.Events) != 0 {
		t.Fatalf("power loss or upgrade reported as tampering: %q", kinds(a.St.Events))
	}
	// stopped by hand
	stopByHand.Store(true)
	defer stopByHand.Store(false)
	a.ended()
	if a.St.Stopped == nil {
		t.Fatal("a stop by hand was not noted")
	}
	a.started()
	if kinds(a.St.Events) != protocol.EventServiceStopped {
		t.Fatalf("stopped service not reported: %q", kinds(a.St.Events))
	}
	// restart for a self-update is not a stop by hand
	a.Updated = "9.9.9"
	a.ended()
	if a.St.Stopped != nil {
		t.Fatal("a self-update restart was noted as a stop by hand")
	}
}
