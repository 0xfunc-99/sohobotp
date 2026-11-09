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
	c, err := client.New(st.PortalURL, st.CAFile)
	if err != nil {
		return nil, err
	}
	return &Agent{St: st, Keys: keys, Client: c, Applier: NewApplier(), Log: Logf, now: time.Now}, nil
}

// Logf writes a timestamped line to stderr (journald on Linux, the log file on Windows).
func Logf(format string, args ...any) {
	fmt.Fprintf(logOutput(), "%s %s\n", time.Now().UTC().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

// Once performs one check-in and applies a configuration if one is received.
// It returns how long to wait before the next check-in.
func (a *Agent) Once() (time.Duration, error) {
	reply, err := a.Client.Checkin(a.St.EndpointID, a.Keys.Sign, protocol.CheckinRequest{Inventory: inventory.Collect(), Applied: a.St.Applied})
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
			now := a.now().Unix()
			summary, applyErr := a.Applier.Apply(cfg)
			a.St.Applied = protocol.Applied{Version: cfg.Version, Status: "applied", At: &now}
			if applyErr != nil {
				a.St.Applied.Status = "failed"
				a.St.Applied.Error = applyErr.Error()
				a.Log("configuration %d FAILED, previous configuration kept: %v", cfg.Version, applyErr)
			} else {
				a.Log("configuration %d applied: %s", cfg.Version, summary)
			}
			return
		}
	}
	// A configuration that does not verify is never applied, and the applied version is
	// not changed: the portal keeps offering it, the administrator sees the error.
	a.St.LastError = "configuration refused: " + err.Error()
	a.Log("SECURITY: %s", a.St.LastError)
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

// Run checks in until stop is closed. A configuration just applied is reported at once.
func (a *Agent) Run(stop <-chan struct{}) {
	a.Log("SohobOTP agent %s started for endpoint %s (%s)", inventory.Version, a.St.EndpointID, a.St.PortalURL)
	for {
		applied := a.St.Applied.Version
		wait, err := a.Once()
		if err != nil {
			a.Log("check-in failed, retry in %s: %v", wait, err)
		} else if a.St.Applied.Version != applied {
			wait = time.Second // report the result right away
		}
		select {
		case <-stop:
			a.Log("SohobOTP agent stopped")
			return
		case <-time.After(wait):
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
