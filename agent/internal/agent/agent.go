// Package agent runs the check-in loop: report inventory and the last applied
// configuration, receive a signed configuration, verify it, apply it, report the result.
// On any error the last applied configuration stays in force (2FA is never removed because
// the portal is unreachable or refuses the machine).
package agent

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"multiotp-portal/agent/internal/client"
	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
)

// Applier applies a verified configuration on this OS.
type Applier interface {
	Apply(cfg *protocol.Config) (summary string, err error)
}

// Agent holds an enrolled machine's identity.
type Agent struct {
	St      *state.State
	Keys    *state.Keys
	Client  *client.Client
	Applier Applier
	Log     func(format string, args ...any)
	now     func() time.Time
	backoff time.Duration
	// Updated is the version installed by a self-update; the process must restart.
	Updated string
	// lastDrift: when a protected agent last checked the machine's settings (tamper.go)
	lastDrift int64
}

// Load prepares the agent from its saved state.
func Load() (*Agent, error) {
	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	keys, err := st.Keys()
	if err != nil {
		return nil, err
	}
	state.SetLocked(protectedNow(st, time.Now().Unix())) // keep the folder's permissions as they are
	c, err := client.New(st.PortalURL, st.CAFile)
	if err != nil {
		return nil, err
	}
	setPackageSource(func(req protocol.PackageRequest, max int64) ([]byte, error) {
		return c.Package(st.EndpointID, keys.Sign, req, max)
	})
	return &Agent{St: st, Keys: keys, Client: c, Applier: NewApplier(), Log: Logf, now: time.Now}, nil
}

// Logf writes a timestamped line to stderr (journald on Linux, the log file on Windows).
func Logf(format string, args ...any) {
	fmt.Fprintf(logOutput(), "%s %s\n", time.Now().UTC().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

// Once performs one check-in and applies a configuration if one is received.
// It returns how long to wait before the next check-in.
func (a *Agent) Once() (time.Duration, error) {
	inv := inventory.Collect()
	inv.Protected = protectedNow(a.St, a.now().Unix())
	sent := len(a.St.Events)
	reply, err := a.Client.Checkin(a.St.EndpointID, a.Keys.Sign, protocol.CheckinRequest{Inventory: inv, Applied: a.St.Applied, Events: a.St.Events})
	if err != nil {
		var apiErr *client.APIError
		if errors.As(err, &apiErr) && apiErr.Code == "disabled" {
			a.St.PortalState = "disabled"
		}
		a.St.LastError = err.Error()
		_ = a.St.Save()
		return a.nextBackoff(), err
	}
	a.backoff = 0
	a.St.Events = a.St.Events[sent:] // received by the portal
	a.confirmUpdate()
	syncPortalCA(a.Client.PortalRoot(), a.Log)
	a.St.LastCheckin = a.now().Unix()
	a.St.LastError = ""
	a.St.PortalState = "active"
	if reply.State != "" {
		a.St.PortalState = reply.State
	}
	if reply.CheckinInterval > 0 {
		a.St.CheckinInterval = reply.CheckinInterval
	}
	if reply.Config != nil {
		a.handle(reply.Config)
	} else if a.St.RetryConfig != nil && a.now().Unix() >= a.St.RetryAt {
		a.retry()
	} else {
		a.watchInstalls()
	}
	if reply.Update != nil && a.Updated == "" {
		a.update(reply.Update)
	}
	if err := a.St.Save(); err != nil {
		return a.nextBackoff(), err
	}
	return a.interval(), nil
}

func (a *Agent) handle(env *protocol.Envelope) {
	portalKey, err := a.St.PortalPublicKey()
	if err == nil {
		var cfg *protocol.Config
		cfg, err = protocol.OpenConfig(env, portalKey, a.St.EndpointID, runtime.GOOS, a.St.Applied.Version, a.Keys.BoxPub, a.Keys.BoxPriv)
		if err == nil {
			a.St.RetryConfig, a.St.RetryCount = nil, 0 // a newer configuration replaces a failed one
			a.apply(cfg, env)
			return
		}
	}
	// A configuration that does not verify is never applied, and the applied version is
	// not changed: the portal keeps offering it, the administrator sees the error.
	a.St.LastError = "configuration refused: " + err.Error()
	a.Log("SECURITY: %s", a.St.LastError)
}

// apply applies a verified configuration and records the result. A failure keeps the
// previous configuration in force and schedules a retry of this one.
func (a *Agent) apply(cfg *protocol.Config, env *protocol.Envelope) {
	now := a.now().Unix()
	a.setProtection(cfg)
	summary, applyErr := a.Applier.Apply(cfg)
	a.St.Applied = protocol.Applied{Version: cfg.Version, Status: "applied", At: &now}
	if applyErr == nil {
		a.St.RetryConfig, a.St.RetryAt, a.St.RetryCount = nil, 0, 0
		a.St.LastConfig = env
		a.lastDrift = now
		a.St.WaitingFor = nil
		if w, ok := a.Applier.(waiter); ok {
			a.St.WaitingFor = w.Waiting(cfg)
		}
		a.Log("configuration %d applied: %s", cfg.Version, summary)
		return
	}
	a.St.Applied.Status = "failed"
	a.St.Applied.Error = applyErr.Error()
	delay := retryDelay(a.St.RetryCount)
	a.St.RetryConfig, a.St.RetryAt = env, now+int64(delay/time.Second)
	a.St.RetryCount++
	a.Log("configuration %d FAILED, previous configuration kept, retry in %s: %v", cfg.Version, delay, applyErr)
}

// retry applies again the configuration that failed. It is the envelope this agent already
// verified and accepted: it is verified again and must be exactly the failed version.
func (a *Agent) retry() {
	env := a.St.RetryConfig
	version := a.St.Applied.Version
	portalKey, err := a.St.PortalPublicKey()
	var cfg *protocol.Config
	if err == nil {
		cfg, err = protocol.OpenConfig(env, portalKey, a.St.EndpointID, runtime.GOOS, version-1, a.Keys.BoxPub, a.Keys.BoxPriv)
	}
	if err != nil || cfg.Version != version || a.St.Applied.Status != "failed" {
		a.St.RetryConfig, a.St.RetryAt, a.St.RetryCount = nil, 0, 0
		return
	}
	a.Log("retrying configuration %d (attempt %d)", version, a.St.RetryCount+1)
	a.apply(cfg, env)
}

// waiter is an Applier that names files the configuration will protect once they exist.
type waiter interface {
	Waiting(cfg *protocol.Config) []string
}

// watchInstalls applies the configuration in force again when a program it protects has been
// installed since (sudo after the agent, on a minimal system), so it is protected at once and
// not only at the next change of the policy.
func (a *Agent) watchInstalls() {
	appeared := ""
	for _, path := range a.St.WaitingFor {
		if _, err := os.Stat(path); err == nil {
			appeared = path
			break
		}
	}
	if appeared == "" || a.St.LastConfig == nil || a.St.Applied.Status != "applied" {
		return
	}
	portalKey, err := a.St.PortalPublicKey()
	if err != nil {
		return
	}
	cfg, err := protocol.OpenConfig(a.St.LastConfig, portalKey, a.St.EndpointID, runtime.GOOS, a.St.Applied.Version-1, a.Keys.BoxPub, a.Keys.BoxPriv)
	if err != nil || cfg.Version != a.St.Applied.Version {
		a.St.WaitingFor = nil
		return
	}
	a.Log("%s was installed: applying configuration %d again to protect it", appeared, cfg.Version)
	a.apply(cfg, a.St.LastConfig)
}

// retryDelay: 1, 2, 4, 8, 16 then every 30 minutes.
func retryDelay(attempt int) time.Duration {
	if attempt > 5 {
		attempt = 5
	}
	d := time.Minute << attempt
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

func (a *Agent) interval() time.Duration {
	s := a.St.CheckinInterval
	if s < 30 {
		s = 30
	}
	if s > 3600 {
		s = 3600
	}
	return time.Duration(s) * time.Second
}

func (a *Agent) nextBackoff() time.Duration {
	if a.backoff == 0 {
		a.backoff = 30 * time.Second
	} else {
		a.backoff *= 2
	}
	if a.backoff > 15*time.Minute {
		a.backoff = 15 * time.Minute
	}
	return a.backoff
}

// Run checks in until stop is closed, or until a self-update needs a restart (returns true).
// A configuration just applied is reported at once.
func (a *Agent) Run(stop <-chan struct{}) bool {
	a.Log("SohobOTP agent %s started for endpoint %s (%s)", inventory.Version, a.St.EndpointID, a.St.PortalURL)
	a.started()
	defer a.ended()
	for {
		applied := a.St.Applied
		wait, err := a.Once()
		if err != nil {
			a.Log("check-in failed, retry in %s: %v", wait, err)
		} else if a.St.Applied.Version != applied.Version || a.St.Applied.Status != applied.Status {
			wait = time.Second // report the result right away
		}
		if a.Updated != "" {
			return true // the service manager starts the new version
		}
		if a.sleep(stop, wait) {
			a.Log("SohobOTP agent stopped")
			return false
		}
	}
}

// Ensure the log goes somewhere even before the service sets it up.
var logFile *os.File

func logOutput() *os.File {
	if logFile != nil {
		return logFile
	}
	return os.Stderr
}
