// sohobotp-agent: the SohobOTP endpoint agent for Linux and Windows.
//
//	sohobotp-agent install --portal URL --token TOKEN --pin HEX [--ca-file PEM] [--no-service]
//	sohobotp-agent install          (an agent downloaded from the portal's "Download agent" page:
//	                                 portal, token, pin and CA certificate are built into it)
//	sohobotp-agent run [--once]
//	sohobotp-agent status
//	sohobotp-agent apply --dry-run --config FILE   (Linux: {"policy": {...}, "secret": "..."})
//	sohobotp-agent uninstall [--code CODE]         (the code: computers with tamper protection)
//	sohobotp-agent upgrade                         (replace an older installed agent by this program)
//	sohobotp-agent version
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"multiotp-portal/agent/internal/agent"
	"multiotp-portal/agent/internal/bundle"
	"multiotp-portal/agent/internal/inventory"
	"multiotp-portal/agent/internal/protocol"
	"multiotp-portal/agent/internal/release"
	"multiotp-portal/agent/internal/state"
)

func main() {
	if len(os.Args) < 2 {
		// an agent downloaded from the portal with its enrolment settings: just run it
		if s, _ := builtIn(); s == nil {
			usage()
			os.Exit(2)
		}
		if agent.RelaunchElevated() { // Windows, double-clicked: ask for administrator rights
			return
		}
		err := install(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sohobotp-agent:", err)
		}
		agent.PauseIfOwnConsole()
		if err != nil {
			os.Exit(1)
		}
		return
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
		err = uninstall(os.Args[2:])
	case "upgrade":
		if err = agent.RequireAdmin(); err == nil {
			err = upgrade()
		}
	case "check-uninstall": // run by the Windows MSI before it removes anything (hidden from the log)
		if err = agent.RequireAdmin(); err == nil {
			code := ""
			if len(os.Args) > 2 {
				code = os.Args[2]
			}
			err = agent.AuthoriseUninstall(code)
		}
	case "release":
		err = releaseCmd(os.Args[2:])
	case "save-token": // run by the Windows MSI (custom action hidden from the log)
		if err = agent.RequireAdmin(); err == nil {
			if len(os.Args) != 3 {
				err = errors.New("usage: save-token TOKEN")
			} else {
				err = agent.SaveBootstrapToken(os.Args[2])
			}
		}
	case "selftest": // run on a downloaded release before it replaces the running agent
		err = selftest(os.Args[2:])
	case "forget": // run by the Windows MSI on uninstall: the next install enrols afresh
		if err = agent.RequireAdmin(); err == nil {
			if err = agent.RemovalAllowed(); err == nil {
				err = state.Remove()
			}
		}
	case "version":
		fmt.Println("sohobotp-agent", inventory.Version)
		if fp := release.Fingerprint(); fp == "" {
			fmt.Println("self-update: disabled (no release key in this build)")
		} else {
			fmt.Println("self-update: signed releases only (release key " + fp + ")")
		}
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
  install            with an agent downloaded from the portal's "Download agent" page (settings built in)
  run [--once]       check in with the portal (the service runs this)
  status             enrolment, last check-in, applied configuration
  apply --dry-run --config FILE   show what a Linux policy would change
  uninstall [--code CODE]   remove the PAM changes (Linux), the service and the agent state; a computer
                     with tamper protection needs its uninstall code (portal: Computers, the computer)
  upgrade            replace an older installed agent by this program (the enrolment is kept)
  forget             delete the agent state only (the Windows MSI runs it on uninstall)
  version
  release keygen --out DIR                       create the OFFLINE release key (keep it off the portal)
  release sign --key FILE --file BIN --version X.Y.Z --os linux|windows --arch amd64|arm64 [--out manifest.json]`)
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
	caPEM := ""
	fromDownload := false
	if *portal == "" && *token == "" && *pin == "" {
		// settings built into an agent downloaded from the portal (options, when given, win)
		s, err := builtIn()
		if err != nil {
			return err
		}
		if s != nil {
			*portal, *token, *pin, caPEM, fromDownload = s.Portal, s.Token, s.Pin, s.CAPEM, true
			fmt.Printf("Enrolment settings built into this agent: portal %s\n", s.Portal)
		}
	}
	if *portal == "" || *token == "" || *pin == "" {
		return errors.New("--portal, --token and --pin are required (or download the agent from the portal's Download agent page: it has them built in)")
	}
	if err := agent.RequireAdmin(); err != nil {
		return err
	}
	if state.Exists() {
		// already enrolled: a newer agent program replaces the installed one, nothing else changes
		if err := upgrade(); err != nil {
			return fmt.Errorf("this machine is already enrolled, and %w", err)
		}
		if fromDownload {
			fmt.Println("Delete the downloaded file: it contains an enrolment token (not used: the machine keeps its enrolment).")
		}
		return nil
	}
	st, err := agent.Enroll(agent.Enrolment{Portal: *portal, Token: *token, Pin: *pin, CAFile: *caFile, CAPEM: caPEM})
	if err != nil {
		return err
	}
	fmt.Printf("Enrolled as endpoint %s.\n", st.EndpointID)
	if fromDownload {
		defer fmt.Println("Delete the downloaded file: it contains the enrolment token (the installed agent does not).")
	}
	a, err := agent.Load()
	if err != nil {
		return err
	}
	if err := a.CheckinAndReport(); err != nil {
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

// builtIn returns the enrolment settings built into this program, if any.
func builtIn() (*bundle.Settings, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil
	}
	s, _, err := bundle.Read(exe)
	return s, err
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	once := fs.Bool("once", false, "check in once (and report a new configuration), then exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*once {
		return agent.RunService()
	}
	a, err := agent.Load()
	if err != nil {
		return err
	}
	if exe, err := os.Executable(); err == nil && agent.StartupCheck(a.St, exe, time.Now().Unix(), agent.Logf) {
		return errors.New("rolled back to the previous version after a failed update: run again")
	}
	agent.CrashHookForTests()
	a.St.RetryAt = 0 // run --once retries a failed configuration now
	if err := a.CheckinAndReport(); err != nil {
		return err
	}
	report(a.St)
	return nil
}

// selftest checks that this binary can run here: the expected version, and (when the machine
// is enrolled) that the agent state and its private keys can be opened. Read-only, no network.
func selftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	expect := fs.String("expect-version", "", "fail unless this binary is that version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *expect != "" && *expect != inventory.Version {
		return fmt.Errorf("this binary is version %s, not %s", inventory.Version, *expect)
	}
	if state.Exists() {
		st, err := state.Load()
		if err != nil {
			return err
		}
		if _, err := st.Keys(); err != nil {
			return fmt.Errorf("cannot open the agent keys: %w", err)
		}
	}
	_ = agent.NewApplier()
	fmt.Println("selftest ok " + inventory.Version)
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
	if st.Protected {
		note := "on (uninstall needs the code from the portal)"
		if time.Now().Unix() < st.UninstallAllowedUntil {
			note = "on, uninstall allowed until " + time.Unix(st.UninstallAllowedUntil, 0).UTC().Format("15:04 UTC") + " (the right code was entered)"
		}
		fmt.Printf("Tamper protection: %s\n", note)
	}
	if st.UpdateBlockedVersion != "" {
		fmt.Printf("Update blocked:  %s (rolled back: it stopped at start; publish a fixed version)\n", st.UpdateBlockedVersion)
	}
	if st.UpdatePending != nil {
		fmt.Printf("Update pending:  %s -> %s (confirmed at the first check-in; %d start(s) so far)\n", st.UpdatePending.From, st.UpdatePending.To, st.UpdatePending.Starts)
	}
	if st.RetryConfig != nil {
		fmt.Printf("Next retry:      %s (attempt %d; run --once retries now)\n",
			time.Unix(st.RetryAt, 0).UTC().Format("2006-01-02 15:04:05 UTC"), st.RetryCount+1)
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

// upgrade replaces the installed agent by this (newer) program.
func upgrade() error {
	old, err := agent.Upgrade()
	if err != nil {
		return err
	}
	fmt.Printf("The installed agent %s was replaced by %s and started again. The machine keeps its enrolment.\n", old, inventory.Version)
	return nil
}

func uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	code := fs.String("code", "", "uninstall code of this computer (portal: Computers, the computer, Uninstall code)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := agent.RequireAdmin(); err != nil {
		return err
	}
	if err := agent.AuthoriseUninstall(*code); err != nil {
		if errors.Is(err, agent.ErrCodeNeeded) || errors.Is(err, agent.ErrWrongCode) {
			return fmt.Errorf("%w\nAn administrator of the SohobOTP portal finds the code under Computers, this computer, Uninstall code. Then:\n  sohobotp-agent uninstall --code XXXX-XXXX-XXXX\n(every attempt is reported to the portal)", err)
		}
		return err
	}
	if byInstaller, err := agent.UninstallByInstaller(); byInstaller {
		if err != nil {
			return err
		}
		fmt.Println("Windows Installer is removing the SohobOTP agent. Delete the computer in the portal if it is retired.")
		return nil
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

// releaseCmd: offline release signing for self-update (stage 4d).
func releaseCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("release keygen|sign")
	}
	switch args[0] {
	case "keygen":
		fs := flag.NewFlagSet("release keygen", flag.ContinueOnError)
		out := fs.String("out", "", "folder for release-private.key")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *out == "" {
			return errors.New("--out is required")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		path := filepath.Join(*out, "release-private.key")
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Printf("Private key: %s (keep it offline, never on the portal)\nPublic key (build agents with it): %s\n", path, base64.StdEncoding.EncodeToString(pub))
		return nil
	case "sign":
		fs := flag.NewFlagSet("release sign", flag.ContinueOnError)
		keyFile := fs.String("key", "", "release-private.key")
		file := fs.String("file", "", "agent binary to sign")
		version := fs.String("version", "", "version built into the binary (x.y.z)")
		goos := fs.String("os", "", "linux or windows")
		arch := fs.String("arch", "", "amd64 or arm64")
		out := fs.String("out", "", "manifest file (default: stdout)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		rawKey, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawKey)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("invalid release key file")
		}
		data, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		m := &release.Manifest{Version: *version, OS: *goos, Arch: *arch, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
		if err := release.Sign(m, ed25519.NewKeyFromSeed(seed)); err != nil {
			return err
		}
		raw, _ := json.MarshalIndent(m, "", "  ")
		if *out == "" {
			fmt.Println(string(raw))
			return nil
		}
		return os.WriteFile(*out, append(raw, '\n'), 0o644)
	}
	return errors.New("release keygen|sign")
}
