//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelfTestRefusesABinaryThatDoesNotStart(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken")
	os.WriteFile(broken, []byte("#!/bin/sh\necho crash >&2\nexit 2\n"), 0o755)
	if err := selfTestCandidate(broken, "0.2.0"); err == nil || !strings.Contains(err.Error(), "does not start") {
		t.Fatalf("broken release accepted: %v", err)
	}
	wrong := filepath.Join(dir, "wrong-version")
	os.WriteFile(wrong, []byte("#!/bin/sh\necho selftest ok 0.1.9\n"), 0o755)
	if err := selfTestCandidate(wrong, "0.2.0"); err == nil {
		t.Fatal("release reporting another version accepted")
	}
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("#!/bin/sh\n[ \"$1 $2 $3\" = \"selftest --expect-version 0.2.0\" ] && echo selftest ok 0.2.0\n"), 0o755)
	if err := selfTestCandidate(good, "0.2.0"); err != nil {
		t.Fatal(err)
	}
}

func TestInstallCandidateKeepsThePrevious(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "sohobotp-agent")
	os.WriteFile(exe, []byte("OLD"), 0o755)
	os.WriteFile(candidatePath(exe), []byte("NEW"), 0o755)
	if err := installCandidate(exe, candidatePath(exe)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "NEW" {
		t.Fatal("new binary not installed")
	}
	if b, _ := os.ReadFile(previousPath(exe)); string(b) != "OLD" {
		t.Fatal("previous binary not kept")
	}
}
