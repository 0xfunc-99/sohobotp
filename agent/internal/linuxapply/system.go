package linuxapply

import (
	"os"
	"os/exec"
	"syscall"
)

// RealSystem runs real commands.
type RealSystem struct{}

func (RealSystem) Run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func (RealSystem) Exists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func signalHUP(p *os.Process) error { return p.Signal(syscall.SIGHUP) }
