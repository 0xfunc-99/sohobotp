package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync/atomic"
	"time"

	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
	"multiotp-portal/agent/internal/tamper"
)

// Tamper protection (computer policy "Tamper protection" in the portal).
//
// When the policy is on, the signed configuration carries tamper_protection and the hash of
// the computer's uninstall code. The agent then:
//
//   - is only removed with that code: "uninstall --code", and the Windows MSI (its
//     CheckUninstall action), ask the running service, which checks the code itself;
//   - locks itself (Windows, tamper_windows.go): administrators cannot stop, reconfigure or
//     delete the service, nor change the agent's program and state folders, and the Uninstall
//     buttons of the agent and of SohobOTP Sign-in are hidden;
//   - watches the machine: every minute it applies its configuration again and, when
//     something had been changed or removed (SohobOTP Sign-in uninstalled, its settings or the
//     PAM files edited), puts it back and tells the portal;
//   - reports uninstall attempts, the service stopped by hand, and the process killed.
//
// A local administrator who is determined can still get around this (take ownership, run as
// SYSTEM, boot another system): the aim is that it cannot be done by accident or quietly.

const (
	// MaxCodeFailures wrong codes in a row block the code for codeLockSeconds.
	MaxCodeFailures = 5
	codeLockSeconds = 15 * 60
	// uninstallWindow: how long the agent may be removed after the right code (seconds).
	uninstallWindow = 10 * 60
	// watchEvery: how often a protected agent looks for requests; driftSeconds: how often it
	// checks the machine's settings.
	watchEvery   = 5 * time.Second
	driftSeconds = 60
	// eventRepeatSeconds: the same event is not raised again within this time.
	eventRepeatSeconds = 3600
	// NoChange is what an Applier answers when the machine already had the configuration.
	NoChange = "nothing to change"
)

// signinMissing tells whether SohobOTP Sign-in is gone (Windows); tests replace it.
var signinMissing = componentMissing

// stopByHand is set by the service code when it is told to stop while the system is not
// shutting down (Windows: a Stop control; Linux: SIGTERM while systemd is not stopping).
var stopByHand atomic.Bool

// protectedNow: tamper protection is in force (on, and no uninstall was just allowed).
func protectedNow(st *state.State, now int64) bool {
	return st.Protected && now >= st.UninstallAllowedUntil
}

func clip(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func stamp(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04 UTC") }

// addEvent queues an event for the portal. The same event (kind and detail) is not queued
// twice within an hour. It returns whether the state changed.
func addEvent(st *state.State, now int64, kind, detail string) bool {
	detail = clip(detail, 300)
	sum := sha256.Sum256([]byte(kind + "\n" + detail))
	key := hex.EncodeToString(sum[:8])
	for k, at := range st.EventSeen {
		if now-at >= eventRepeatSeconds {
			delete(st.EventSeen, k)
		}
	}
	if _, seen := st.EventSeen[key]; seen {
		return false
	}
	if st.EventSeen == nil {
		st.EventSeen = map[string]int64{}
	}
	st.EventSeen[key] = now
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	st.Events = append(st.Events, protocol.Event{ID: hex.EncodeToString(id), At: now, Kind: kind, Detail: detail})
	if len(st.Events) > protocol.MaxEvents {
		st.Events = st.Events[len(st.Events)-protocol.MaxEvents:]
	}
	return true
}

func (a *Agent) event(kind, detail string) bool {
	if !addEvent(a.St, a.now().Unix(), kind, detail) {
		return false
	}
	a.Log("TAMPER: %s: %s", kind, detail)
	return true
}

// setProtection takes the tamper part of a verified configuration. It is in force from that
// moment, also when the rest of the configuration fails to apply.
func (a *Agent) setProtection(cfg *protocol.Config) {
	var p protocol.Protection
	_ = json.Unmarshal(cfg.Policy, &p)
	if p.TamperProtection != a.St.Protected {
		a.Log("tamper protection turned %s by the portal", map[bool]string{true: "on", false: "off"}[p.TamperProtection])
	}
	a.St.Protected, a.St.UninstallCodeHash = p.TamperProtection, p.UninstallCodeHash
	if !p.TamperProtection {
		a.St.UninstallCodeHash, a.St.UninstallFailures, a.St.UninstallLockedUntil, a.St.UninstallAllowedUntil = "", 0, 0, 0
	}
	a.enforce(false)
}

// enforce locks or unlocks the machine to match the state. again: lock even if the state says
// it is locked already (at start: something may have been undone while the agent was stopped).
func (a *Agent) enforce(again bool) bool {
	want := protectedNow(a.St, a.now().Unix())
	state.SetLocked(want)
	if want == a.St.Locked && !(want && again) {
		return false
	}
	if err := lockMachine(want); err != nil {
		a.Log("tamper protection: %v", err)
	}
	changed := a.St.Locked != want
	a.St.Locked = want
	return changed
}

// started runs once when the service starts: it reports a service that had been stopped by
// hand or killed, and notes that the agent is running.
func (a *Agent) started() {
	now := a.now().Unix()
	if r := a.St.Running; r != nil && a.St.Protected && r.Version == inventory.Version {
		// same version, and the system has not restarted since: the process was ended
		if boot := bootTime(); boot > 0 && boot < r.At {
			a.event(protocol.EventAgentKilled, "the agent process ended without being stopped (it had been running since "+stamp(r.At)+") and was started again")
		}
	}
	if s := a.St.Stopped; s != nil && a.St.Protected && s.Version == inventory.Version {
		a.event(protocol.EventServiceStopped, fmt.Sprintf("the agent service was stopped at %s and started again %d minute(s) later", stamp(s.At), (now-s.At+59)/60))
	}
	a.St.Stopped = nil
	a.St.Running = &state.RunMarker{At: now, Version: inventory.Version, PID: os.Getpid()}
	a.enforce(true)
	_ = a.St.Save()
}

// ended runs when the service stops normally (stop, shutdown, restart after a self-update).
func (a *Agent) ended() {
	now := a.now().Unix()
	a.St.Running = nil
	if stopByHand.Load() && a.Updated == "" && protectedNow(a.St, now) {
		a.St.Stopped = &state.RunMarker{At: now, Version: inventory.Version}
	}
	_ = a.St.Save()
}

// sleep waits for the next check-in. A protected agent wakes every few seconds to answer
// uninstall requests and to check the machine. It returns true when stop was closed.
func (a *Agent) sleep(stop <-chan struct{}, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		step := time.Until(deadline)
		if step <= 0 {
			return false
		}
		if a.St.Protected && step > watchEvery {
			step = watchEvery
		}
		select {
		case <-stop:
			return true
		case <-time.After(step):
		}
		if a.St.Protected && a.watch() {
			_ = a.St.Save()
		}
	}
}

// watch is one look at the machine by a protected agent. It returns whether the state changed.
func (a *Agent) watch() bool {
	now := a.now().Unix()
	changed := a.answerRequests(now)
	if a.enforce(false) {
		changed = true
	}
	if protectedNow(a.St, now) && now-a.lastDrift >= driftSeconds {
		a.lastDrift = now
		if a.checkDrift() {
			changed = true
		}
	}
	return changed
}

// checkDrift applies the configuration in force again. Appliers only write what differs, so
// a machine nobody touched is left alone; anything put back is reported.
func (a *Agent) checkDrift() bool {
	changed := false
	if note := checkService(); note != "" {
		changed = a.event(protocol.EventServiceChanged, note)
	}
	if a.St.LastConfig == nil || a.St.Applied.Status != "applied" || a.St.RetryConfig != nil {
		return changed
	}
	portalKey, err := a.St.PortalPublicKey()
	if err != nil {
		return changed
	}
	cfg, err := protocol.OpenConfig(a.St.LastConfig, portalKey, a.St.EndpointID, runtime.GOOS, a.St.Applied.Version-1, a.Keys.BoxPub, a.Keys.BoxPriv)
	if err != nil || cfg.Version != a.St.Applied.Version {
		return changed
	}
	missing := signinMissing()
	summary, err := a.Applier.Apply(cfg)
	switch {
	case err != nil && missing:
		return a.event(protocol.EventSigninRemoved, "SohobOTP Sign-in is no longer installed and could not be installed again: "+err.Error()) || changed
	case err != nil:
		return a.event(protocol.EventProtectionBroken, "the settings could not be checked or put back: "+err.Error()) || changed
	case missing:
		return a.event(protocol.EventSigninRemoved, "SohobOTP Sign-in had been removed; put back ("+summary+")") || changed
	case summary != NoChange:
		return a.event(protocol.EventSettingsRestored, "settings changed on the computer were put back: "+summary) || changed
	}
	return changed
}

// --- uninstall with the code -------------------------------------------------------------

// ErrCodeNeeded and ErrWrongCode are what an uninstall without the right code gets.
var (
	ErrCodeNeeded = errors.New("this computer has tamper protection: the uninstall code is needed")
	ErrWrongCode  = errors.New("wrong uninstall code")
)

// checkCode checks an uninstall code against the state and counts wrong ones.
func checkCode(st *state.State, now int64, code string) error {
	if tamper.Normalise(code) == "" {
		return ErrCodeNeeded
	}
	if now < st.UninstallLockedUntil {
		return fmt.Errorf("too many wrong uninstall codes: try again in %d minute(s)", (st.UninstallLockedUntil-now+59)/60)
	}
	if tamper.Check(st.UninstallCodeHash, st.EndpointID, code) {
		st.UninstallFailures = 0
		return nil
	}
	st.UninstallFailures++
	if st.UninstallFailures >= MaxCodeFailures {
		st.UninstallFailures, st.UninstallLockedUntil = 0, now+codeLockSeconds
	}
	return ErrWrongCode
}

type uninstallRequest struct {
	ID   string `json:"id"`
	Code string `json:"code"`
}

type uninstallAnswer struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

var requestID = regexp.MustCompile(`^[0-9a-f]{16}$`)

func requestFile() string         { return filepath.Join(state.RequestDir(), "uninstall.req") }
func answerFile(id string) string { return filepath.Join(state.RequestDir(), "uninstall."+id+".ans") }

// answerRequests handles an uninstall request left by "uninstall --code" or the MSI. The
// service checks the code itself: what the requesting program says is never trusted.
func (a *Agent) answerRequests(now int64) bool {
	info, err := os.Stat(requestFile())
	if err != nil {
		return false
	}
	raw, _ := os.ReadFile(requestFile())
	_ = os.Remove(requestFile())
	var req uninstallRequest
	if now-info.ModTime().Unix() > 120 || len(raw) > 4096 || json.Unmarshal(raw, &req) != nil || !requestID.MatchString(req.ID) {
		return false
	}
	answer := uninstallAnswer{OK: true}
	if protectedNow(a.St, now) {
		if err := checkCode(a.St, now, req.Code); err != nil {
			answer = uninstallAnswer{Message: err.Error()}
			a.event(protocol.EventUninstallRefused, "someone tried to uninstall the agent: "+err.Error())
		} else {
			a.St.UninstallAllowedUntil = now + uninstallWindow
			a.event(protocol.EventUninstalled, "the right uninstall code was entered: the agent may be removed until "+stamp(a.St.UninstallAllowedUntil))
			a.enforce(false) // unlock: the uninstall itself runs as the administrator
		}
	}
	_ = a.St.Save()
	a.flushEvents() // tell the portal now: after an uninstall there is no later
	out, _ := json.Marshal(answer)
	_ = os.WriteFile(answerFile(req.ID), out, 0o600)
	return true
}

// flushEvents sends the queued events with an extra check-in; a configuration in the answer
// is left for the regular check-in.
func (a *Agent) flushEvents() {
	if len(a.St.Events) == 0 || a.Client == nil {
		return
	}
	sent := len(a.St.Events)
	inv := inventory.Collect()
	inv.Protected = protectedNow(a.St, a.now().Unix())
	if _, err := a.Client.Checkin(a.St.EndpointID, a.Keys.Sign, protocol.CheckinRequest{Inventory: inv, Applied: a.St.Applied, Events: a.St.Events}); err == nil {
		a.St.Events = a.St.Events[sent:]
		_ = a.St.Save()
	}
}

// RemovalAllowed tells whether the agent's state may be deleted now ("forget", run by the
// Windows MSI at uninstall): always without tamper protection, else only after the code.
func RemovalAllowed() error {
	if !state.Exists() {
		return nil
	}
	st, err := state.Load()
	if err != nil || !protectedNow(st, time.Now().Unix()) {
		return nil
	}
	return ErrCodeNeeded
}

// AuthoriseUninstall is the first step of every uninstall. Without tamper protection it
// allows it. With it, the running service is asked to check the code; when the service is not
// running (and this program may change the agent state) the code is checked here.
func AuthoriseUninstall(code string) error {
	if !state.Exists() {
		return nil
	}
	st, err := state.Load()
	now := time.Now().Unix()
	if err != nil || !protectedNow(st, now) {
		return nil
	}
	if !serviceRunning() {
		startService()
	}
	if serviceRunning() {
		return askService(code)
	}
	// no service to ask: check here (root on Linux; SYSTEM on Windows, the state being locked)
	state.SetLocked(true)
	if err := checkCode(st, now, code); err != nil {
		addEvent(st, now, protocol.EventUninstallRefused, "someone tried to uninstall the agent while its service was not running: "+err.Error())
		_ = st.Save()
		return err
	}
	st.UninstallAllowedUntil = now + uninstallWindow
	addEvent(st, now, protocol.EventUninstalled, "the right uninstall code was entered while the service was not running")
	if err := st.Save(); err != nil {
		return fmt.Errorf("the agent service is not running and this program may not change the agent state (%v): start the service, then try again", err)
	}
	state.SetLocked(false)
	if err := lockMachine(false); err != nil {
		return err
	}
	st.Locked = false
	return st.Save()
}

// askService leaves the request for the service and waits for its answer.
func askService(code string) error {
	if err := state.EnsureRequestDir(); err != nil {
		return err
	}
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	id := hex.EncodeToString(raw)
	body, _ := json.Marshal(uninstallRequest{ID: id, Code: code})
	tmp := requestFile() + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, requestFile()); err != nil {
		return err
	}
	defer os.Remove(answerFile(id))
	for end := time.Now().Add(45 * time.Second); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		out, err := os.ReadFile(answerFile(id))
		if err != nil {
			continue
		}
		var answer uninstallAnswer
		if json.Unmarshal(out, &answer) != nil {
			continue // still being written
		}
		if answer.OK {
			return nil
		}
		switch answer.Message {
		case ErrCodeNeeded.Error():
			return ErrCodeNeeded
		case ErrWrongCode.Error():
			return ErrWrongCode
		}
		return errors.New(answer.Message)
	}
	_ = os.Remove(requestFile())
	return errors.New("the SohobOTP agent service did not answer within 45 seconds: try again")
}
