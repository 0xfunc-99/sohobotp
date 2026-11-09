//go:build !windows

package agent

import (
	"os"
	"os/signal"
	"syscall"
)

func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
}
