//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"multiotp-portal/agent/internal/linuxapply"
	"multiotp-portal/agent/internal/protocol"
)

type linuxApplier struct{ a *linuxapply.Applier }

// NewApplier returns the PAM applier.
func NewApplier() Applier {
	return linuxApplier{&linuxapply.Applier{Sys: linuxapply.RealSystem{}}}
}

func (l linuxApplier) Apply(cfg *protocol.Config) (string, error) {
	var p protocol.LinuxPolicy
	if err := json.Unmarshal(cfg.Policy, &p); err != nil {
		return "", fmt.Errorf("Linux policy not readable: %w", err)
	}
	changes, err := l.a.Apply(&p, cfg.Secrets["radius_secret"])
	if err != nil {
		return "", err
	}
	return summarise(changes), nil
}

// Waiting: protected services not installed yet (see Agent.watchInstalls).
func (l linuxApplier) Waiting(cfg *protocol.Config) []string {
	var p protocol.LinuxPolicy
	if err := json.Unmarshal(cfg.Policy, &p); err != nil {
		return nil
	}
	return l.a.Waiting(&p)
}

func summarise(changes []linuxapply.Change) string {
	if len(changes) == 0 {
		return NoChange
	}
	var parts []string
	for _, c := range changes {
		verb := "wrote"
		if c.Content == nil {
			verb = "removed"
		}
		parts = append(parts, verb+" "+c.Path)
	}
	return strings.Join(parts, ", ")
}

// DryRun shows the changes of a Linux policy without applying it (apply --dry-run).
func DryRun(policy protocol.LinuxPolicy, secret string) (string, error) {
	changes, err := (&linuxapply.Applier{Sys: linuxapply.RealSystem{}, DryRun: true}).Apply(&policy, secret)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range changes {
		if c.Content == nil {
			fmt.Fprintf(&b, "--- remove %s\n", c.Path)
			continue
		}
		content := *c.Content
		if secret != "" {
			content = strings.ReplaceAll(content, secret, "********")
		}
		fmt.Fprintf(&b, "--- write %s\n%s", c.Path, content)
	}
	if len(changes) == 0 {
		b.WriteString("nothing to change\n")
	}
	return b.String(), nil
}
