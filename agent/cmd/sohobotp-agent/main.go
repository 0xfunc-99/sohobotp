// sohobotp-agent: the SohobOTP endpoint agent for Linux and Windows.
//
//	sohobotp-agent install --portal URL --token TOKEN --pin HEX [--ca-file PEM] [--no-service]
//	sohobotp-agent run [--once]
//	sohobotp-agent status
//	sohobotp-agent apply --dry-run --config FILE   (Linux: {"policy": {...}, "secret": "..."})
//	sohobotp-agent uninstall
//	sohobotp-agent version
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"multiotp-portal/agent/internal/agent"
	"multiotp-portal/agent/internal/client"
	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/state"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "install":
		err = install(os.Args[2:])
	case "run":
		err = run(os.Args[2:])
	case "status":
		err = status()
	case "apply":
		err = dryRun(os.Args[2:])
	case "uninstall":
		err = uninstall()
	case "version":
		fmt.Println("sohobotp-agent", inventory.Version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sohobotp-agent:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `SohobOTP agent `+inventory.Version+`
  install --portal https://portal.example.com --token TOKEN --pin PIN [--ca-file ca.pem] [--no-service]
  run [--once]       check in with the portal (the service runs this)
  status             enrolment, last check-in, applied configuration
  apply --dry-run --config FILE   show what a Linux policy would change
  uninstall          remove the PAM changes (Linux), the service and the agent state
  version`)
}

func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	portal := fs.String("portal", "", "portal address, https://...")
	token := fs.String("token", "", "enrolment token (from the portal's Enrol endpoints page)")
	pin := fs.String("pin", "", "portal key pin shown on the Enrol endpoints page")
	caFile := fs.String("ca-file", "", "CA certificate (PEM) of the portal, if not publicly trusted")
	noService := fs.Bool("no-service", false, "enrol only, do not install the service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *portal == "" || *token == "" || *pin == "" {
		return errors.New("--portal, --token and --pin are required")
	}
	if err := agent.RequireAdmin(); err != nil {
		return err
	}
	if state.Exists() {
		st, _ := state.Load()
		id := ""
		if st != nil {
			id = st.EndpointID
		}
		return fmt.Errorf("this machine is already enrolled (endpoint %s): run uninstall first", id)
	}
	st := &state.State{PortalURL: *portal, Applied: protocol.Applied{Status: "none"}}
	if *caFile != "" {
		// keep a copy next to the state: the original file may move
		if err := os.MkdirAll(state.Dir(), 0o700); err != nil {
			return err
		}
		dst := filepath.Join(state.Dir(), "portal-ca.pem")
		if err := copyFile(*caFile, dst); err != nil {
			return fmt.Errorf("cannot copy the CA file: %w", err)
		}
		st.CAFile = dst
	}
	c, err := client.New(*portal, st.CAFile)
	if err != nil {
		return err
	}
	keys, err := state.NewKeys()
	if err != nil {
		return err
	}
	reply, err := c.Enroll(*token, keys, inventory.Collect())
	if err != nil {
		return err
	}
	portalKey, err := decodeKey(reply.PortalKey)
	if err != nil {
		return err
	}
	if protocol.Pin(portalKey) != protocol.NormalisePin(*pin) {
		return errors.New("the portal's key does not match the pin: not enrolled (wrong portal, or someone is intercepting the connection); delete the new endpoint in the portal")
	}
	st.EndpointID = reply.EndpointID
	st.PortalKey = reply.PortalKey
	st.CheckinInterval = reply.CheckinInterval
	st.PortalState = "active"
	st.Store(keys)
	if err := st.Save(); err != nil {
		return err
	}
	fmt.Printf("Enrolled as endpoint %s.\n", st.EndpointID)
	a, err := agent.Load()
	if err != nil {
		return err
	}
	if err := checkinAndReport(a); err != nil {
		fmt.Fprintln(os.Stderr, "first check-in failed (the service retries):", err)
	}
	report(a.St)
	if *noService {
		return nil
	}
	if err := agent.InstallService(); err != nil {
		return fmt.Errorf("enrolled, but the service could not be installed: %w", err)
	}
	fmt.Println("Service installed and started.")
	return nil
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	once := fs.Bool("once", false, "check in once (and report a new configuration), then exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := agent.Load()
	if err != nil {
		return err
	}
	if !*once {
		return agent.RunService(a)
	}
	if err := checkinAndReport(a); err != nil {
		return err
	}
	report(a.St)
	return nil
}

// checkinAndReport checks in once and, when a configuration was applied, reports the
// result to the portal right away.
func checkinAndReport(a *agent.Agent) error {
	before := a.St.Applied.Version
	if _, err := a.Once(); err != nil {
		return err
	}
	if a.St.Applied.Version != before {
		time.Sleep(time.Second)
		if _, err := a.Once(); err != nil {
			return err
		}
	}
	return nil
}

func status() error {
	st, err := state.Load()
	if err != nil {
		return err
	}
	report(st)
	return nil
}

func report(st *state.State) {
	last := "never"
	if st.LastCheckin > 0 {
		last = time.Unix(st.LastCheckin, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	}
	portalState := st.PortalState
	if portalState == "pending" {
		portalState = "waiting for approval in the portal"
	}
	fmt.Printf("Portal:          %s\nEndpoint:        %s\nState:           %s\nLast check-in:   %s\nConfiguration:   version %d, %s\n",
		st.PortalURL, st.EndpointID, portalState, last, st.Applied.Version, st.Applied.Status)
	if st.Applied.Error != "" {
		fmt.Printf("Apply error:     %s\n", st.Applied.Error)
	}
	if st.LastError != "" {
		fmt.Printf("Last error:      %s\n", st.LastError)
	}
}

func dryRun(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "required: only show the changes")
	file := fs.String("config", "", `JSON file {"policy": {...}, "secret": "..."}`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*dry || *file == "" {
		return errors.New("only apply --dry-run --config FILE is supported (configurations come from the portal)")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var in struct {
		Policy protocol.LinuxPolicy `json:"policy"`
		Secret string               `json:"secret"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	out, err := agent.DryRun(in.Policy, in.Secret)
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

func uninstall() error {
	if err := agent.RequireAdmin(); err != nil {
		return err
	}
	if err := agent.UninstallService(); err != nil {
		return err
	}
	if err := state.Remove(); err != nil {
		return err
	}
	fmt.Println("SohobOTP agent removed. Delete the endpoint in the portal if the machine is retired.")
	return nil
}

func decodeKey(s string) ([]byte, error) {
	key, err := base64Decode(s)
	if err != nil || len(key) != 32 {
		return nil, errors.New("the portal sent an invalid key")
	}
	return key, nil
}

func copyFile(from, to string) error {
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

func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
