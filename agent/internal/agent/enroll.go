package agent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"multiotp-portal/agent/internal/client"
	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
)

// Enrolment is what an install needs: from the command line, or from the registry values
// written by the MSI (Group Policy rollout).
type Enrolment struct {
	Portal string
	Token  string
	Pin    string
	CAFile string
}

// ErrNoBootstrap means no enrolment values were found for an automatic enrolment.
var ErrNoBootstrap = errors.New("not enrolled and no enrolment values (run install, or deploy the MSI with PORTAL, TOKEN and PIN)")

// Enroll registers the machine and saves its state. The portal's key must match the pin,
// otherwise nothing is saved.
func Enroll(e Enrolment) (*state.State, error) {
	if e.Portal == "" || e.Token == "" || e.Pin == "" {
		return nil, errors.New("portal, token and pin are required")
	}
	if state.Exists() {
		st, _ := state.Load()
		id := ""
		if st != nil {
			id = st.EndpointID
		}
		return nil, fmt.Errorf("this machine is already enrolled (endpoint %s): run uninstall first", id)
	}
	st := &state.State{PortalURL: e.Portal, Applied: protocol.Applied{Status: "none"}}
	if e.CAFile != "" {
		// keep a copy next to the state: the original file may move
		if err := os.MkdirAll(state.Dir(), 0o700); err != nil {
			return nil, err
		}
		dst := filepath.Join(state.Dir(), "portal-ca.pem")
		if err := copyPlain(e.CAFile, dst); err != nil {
			return nil, fmt.Errorf("cannot copy the CA file: %w", err)
		}
		st.CAFile = dst
	}
	c, err := client.New(e.Portal, st.CAFile)
	if err != nil {
		return nil, err
	}
	keys, err := state.NewKeys()
	if err != nil {
		return nil, err
	}
	reply, err := c.Enroll(e.Token, keys, inventory.Collect())
	if err != nil {
		return nil, err
	}
	portalKey, err := base64.StdEncoding.DecodeString(reply.PortalKey)
	if err != nil || len(portalKey) != 32 {
		return nil, errors.New("the portal sent an invalid key")
	}
	if protocol.Pin(portalKey) != protocol.NormalisePin(e.Pin) {
		return nil, errors.New("the portal's key does not match the pin: not enrolled (wrong portal, or someone is intercepting the connection); delete the new endpoint in the portal")
	}
	st.EndpointID = reply.EndpointID
	st.PortalKey = reply.PortalKey
	st.CheckinInterval = reply.CheckinInterval
	st.PortalState = "active"
	if err := st.Store(keys); err != nil {
		return nil, err
	}
	if err := st.Save(); err != nil {
		return nil, err
	}
	return st, nil
}

// CheckinAndReport checks in once and, when a configuration was applied, reports the
// result to the portal right away.
func (a *Agent) CheckinAndReport() error {
	before := a.St.Applied
	if _, err := a.Once(); err != nil {
		return err
	}
	if a.St.Applied.Version != before.Version || a.St.Applied.Status != before.Status {
		time.Sleep(time.Second)
		if _, err := a.Once(); err != nil {
			return err
		}
	}
	return nil
}

// Serve is what the service runs: enrol from the bootstrap values if needed (retrying),
// then check in until stop is closed. It returns true when a self-update needs a restart.
func Serve(stop <-chan struct{}) bool {
	cleanupOldBinary()
	wait := 30 * time.Second
	if state.Exists() {
		clearBootstrapToken() // a repair or upgrade may have written TOKEN again
	}
	for !state.Exists() {
		e, err := readBootstrap()
		if err == nil {
			_, err = Enroll(e)
			if err == nil {
				clearBootstrapToken()
				Logf("enrolled from the installer values")
				break
			}
		}
		Logf("not enrolled yet, retry in %s: %v", wait, err)
		select {
		case <-stop:
			return false
		case <-time.After(wait):
		}
		if wait < 15*time.Minute {
			wait *= 2
		}
	}
	a, err := Load()
	if err != nil {
		Logf("cannot start: %v", err)
		<-stop
		return false
	}
	if exe, err := os.Executable(); err == nil && StartupCheck(a.St, exe, time.Now().Unix(), Logf) {
		return true // rolled back: the service manager starts the previous version
	}
	CrashHookForTests()
	return a.Run(stop)
}

func copyPlain(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
