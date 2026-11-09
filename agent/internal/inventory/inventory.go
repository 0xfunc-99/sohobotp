// Package inventory collects what the agent reports about the machine.
package inventory

import (
	"net"
	"os"
	"runtime"
	"sort"

	"multiotp-portal/agent/internal/protocol"
)

// Version of the agent, set at build time with -ldflags "-X ...inventory.Version=x".
var Version = "0.1.0"

// Collect returns the inventory of this machine. It never fails: unknown fields stay empty.
func Collect() protocol.Inventory {
	host, _ := os.Hostname()
	inv := protocol.Inventory{
		Hostname:     host,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		IPs:          addresses(),
		AgentVersion: Version,
	}
	platform(&inv)
	return inv
}

func addresses() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() {
			continue
		}
		ips = append(ips, n.IP.String())
	}
	sort.Strings(ips)
	if len(ips) > 32 {
		ips = ips[:32]
	}
	return ips
}
